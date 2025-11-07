import enum
import logging
from collections.abc import Callable, Sequence
from copy import copy
from dataclasses import dataclass
from pathlib import Path
from typing import overload

import claripy
import claripy.ast as ast
import json5

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SecurityState(enum.Enum):
    # Ordered by increasing security level
    # IDAU can have all possible states
    # SAU can only have Non-secure and Non-secure callable
    NONSECURE = 0
    NONSECURE_CALLABLE = 1
    SECURE = 2


class ProcessorSecurityState(enum.Enum):
    NONSECURE = 0
    SECURE = 2


class ProcessorPrivilegeLevel(enum.Enum):
    UNPRIVILEGED = 0
    PRIVILEGED = 2


@dataclass
class SecurityRegion:
    start_address: int
    end_address: int
    security_state: SecurityState

    def mergeable(self, other) -> bool:
        return isinstance(other, self.__class__) and self.end_address + 1 >= other.start_address and self.security_state == other.security_state


@dataclass
class AttributionUnitRegion(SecurityRegion):
    region_number: int
    is_exempted: bool

    def __repr__(self) -> str:
        return f"Region(region_number={self.region_number}, start_address=0x{self.start_address:08X}, end_address=0x{self.end_address:08X}, security_state={self.security_state.name}, is_exempted={self.is_exempted})"

    def mergeable(self, other) -> bool:
        return super().mergeable(other) and self.is_exempted == other.is_exempted and self.region_number == other.region_number


@dataclass
class FlattenedRegion(SecurityRegion):
    sau_region_number: int
    idau_region_number: int

    def __repr__(self) -> str:
        return f"FlattenedRegion(sau_region_number={self.sau_region_number}, idau_region_number={self.idau_region_number}, start_address=0x{self.start_address:08X}, end_address=0x{self.end_address:08X}, security_state={self.security_state.name})"

    def mergeable(self, other) -> bool:
        return super().mergeable(other) and self.sau_region_number == other.sau_region_number and self.idau_region_number == other.idau_region_number


@dataclass
class IDAURegion(AttributionUnitRegion):
    def __repr__(self) -> str:
        return f"IDAU{super().__repr__()}"


@dataclass
class SAURegion(AttributionUnitRegion):
    def __repr__(self) -> str:
        return f"SAU{super().__repr__()}"


@overload
def merge_adjacent_regions(
    regions: Sequence[AttributionUnitRegion],
) -> Sequence[AttributionUnitRegion]: ...


@overload
def merge_adjacent_regions(regions: Sequence[FlattenedRegion]) -> Sequence[FlattenedRegion]: ...


def merge_adjacent_regions(regions):
    if len(regions) <= 1:
        return regions

    sorted_regions = sorted(regions, key=lambda r: r.start_address)
    merged_regions: list = []

    for i in range(len(sorted_regions)):
        curr_region = sorted_regions[i]
        if len(merged_regions) == 0:
            merged_regions.append(curr_region)
        else:
            last_region = merged_regions[-1]
            if last_region.mergeable(curr_region):
                merged_region = copy(last_region)
                merged_region.end_address = max(last_region.end_address, curr_region.end_address)
                merged_regions[-1] = merged_region
            else:
                merged_regions.append(curr_region)
    return merged_regions


class BaseAttributionUnit[T: AttributionUnitRegion]:
    """Generic base class for Attribution Units (IDAU, SAU)"""

    def __init__(self, bits: int = 32):
        self.regions: list[T] = []
        self.bits = bits

    def add_region(self, region: T):
        self.regions.append(region)

    def get_region_constructor(self) -> type[T]:
        raise NotImplementedError

    def _nested_attribution_check(
        self,
        address: ast.BV,
        i: int,
        match: Callable[[T], int | ast.BV],
        default: int | ast.BV,
    ) -> ast.BV:
        # TODO: if multiple regions match, no region should be returned
        region = self.regions[i]
        return claripy.If(
            claripy.And(
                # Both inclusive, see ARMv8-M Architecture Reference Manual: R_KRSC
                region.start_address <= address,
                address <= region.end_address,
            ),
            # If address is in this region, return the result of the match function
            match(region),
            self._nested_attribution_check(address, i + 1, match, default)
            if i + 1 < len(self.regions)
            # If no region matches, return default value
            else default,
        )

    def get_flattened_regions(self) -> Sequence[T]:
        if len(self.regions) == 0:
            return [
                self.get_region_constructor()(
                    region_number=-1,
                    start_address=0x0,
                    end_address=(2**self.bits) - 1,
                    security_state=SecurityState.SECURE,
                    is_exempted=False,
                ),
            ]

        sorted_merged_regions = sorted(self.regions, key=lambda r: r.start_address)

        if sorted_merged_regions[0].start_address > 0:
            # Add a secure region before the first region
            curr_region = self.get_region_constructor()(
                region_number=-1,
                start_address=0,
                end_address=sorted_merged_regions[0].start_address - 1,
                security_state=SecurityState.SECURE,
                is_exempted=False,
            )
        else:
            curr_region = copy(sorted_merged_regions.pop(0))

        regions: Sequence[T] = []
        while sorted_merged_regions:
            next_region_start = sorted_merged_regions[0].start_address
            if curr_region.end_address >= next_region_start:
                # Overlap detected
                overlap_start = next_region_start
                overlap_end = min(curr_region.end_address, sorted_merged_regions[0].end_address)

                # Get first part of current region (before overlap)
                if curr_region.start_address < overlap_start:
                    temp_region = copy(curr_region)
                    temp_region.end_address = overlap_start - 1
                    regions.append(temp_region)

                # Get overlapping part
                temp_region = copy(curr_region)
                temp_region.region_number = -1
                temp_region.start_address = overlap_start
                temp_region.end_address = overlap_end
                temp_region.security_state = SecurityState.SECURE
                regions.append(temp_region)

                # Update current or next region to remaining part (after overlap)
                if curr_region.end_address > overlap_end:
                    # Current region has remaining part
                    # So next region is fully consumed
                    sorted_merged_regions.pop(0)
                elif sorted_merged_regions[0].end_address > overlap_end:
                    # Next region has remaining part
                    curr_region = sorted_merged_regions.pop(0)
                else:
                    # Both regions are fully consumed
                    if len(sorted_merged_regions) <= 1:
                        curr_region = None
                        break
                    sorted_merged_regions.pop(0)
                    curr_region = sorted_merged_regions.pop(0)

                # Throw away any other regions that are fully consumed by the overlap
                while len(sorted_merged_regions) > 0 and sorted_merged_regions[0].end_address <= overlap_end:
                    sorted_merged_regions.pop(0)

                curr_region.start_address = overlap_end + 1
            else:
                # No overlap
                regions.append(curr_region)

                if curr_region.end_address + 1 == next_region_start:
                    # Regions touch
                    pass
                else:
                    # Space between regions
                    regions.append(
                        self.get_region_constructor()(
                            region_number=-1,
                            start_address=curr_region.end_address + 1,
                            end_address=next_region_start - 1,
                            security_state=SecurityState.SECURE,
                            is_exempted=False,
                        ),
                    )

                curr_region = copy(sorted_merged_regions.pop(0))

        if curr_region is not None:
            regions.append(curr_region)
        # Fill the rest of the address space with a secure region
        if regions[-1].end_address < (2**self.bits) - 1:
            regions.append(
                self.get_region_constructor()(
                    region_number=-1,
                    start_address=regions[-1].end_address + 1,
                    end_address=(2**self.bits) - 1,
                    security_state=SecurityState.SECURE,
                    is_exempted=False,
                ),
            )
        # merge_adjacent_regions returns a Sequence of regions; mypy can have trouble
        # proving it's the same generic T, so silence the return-value type check here.
        return merge_adjacent_regions(regions)  # type: ignore[return-value]


class IDAU(BaseAttributionUnit[IDAURegion]):
    """Models the Implementation Defined Attribution Unit (IDAU)"""

    def __init__(self, filename: str = "", bits: int = 32):
        super().__init__(bits)

        if not filename:
            return
        if not Path(filename).exists():
            raise FileNotFoundError(f"IDAU configuration for file '{filename}' not found.")
        with Path(filename).open() as f:
            idau_config = json5.load(f)
            for i, region in enumerate(idau_config["regions"]):
                security_attribute = region["security_attribute"]
                if security_attribute == "nonsecure":
                    sec_state = SecurityState.NONSECURE
                elif security_attribute == "secure":
                    sec_state = SecurityState.SECURE
                elif security_attribute == "nonsecure_callable":
                    sec_state = SecurityState.NONSECURE_CALLABLE
                elif security_attribute == "exempted":
                    # TODO: there are also architectural exemptions, handle those too
                    sec_state = SecurityState.SECURE
                else:
                    raise ValueError(f"Unknown security attribute: {security_attribute}")

                self.add_region(
                    IDAURegion(
                        region_number=region["number"],
                        start_address=region["start_address"],
                        end_address=region["end_address"],
                        security_state=sec_state,
                        is_exempted=(security_attribute == "exempted"),
                    ),
                )

    def get_region_constructor(self) -> type[IDAURegion]:
        return IDAURegion

    def __repr__(self) -> str:
        return f"""IDAU(
    regions=[
        {",\n\t".join(repr(region) for region in self.regions)}
    ]
)"""


class SAU(BaseAttributionUnit[SAURegion]):
    """Models the Security Attribution Unit (SAU)"""

    def __init__(self, bits: int = 32):
        super().__init__(bits)
        # ENABLE bit
        # 0 = SAU disabled, 1 = SAU enabled
        self.ENABLE: bool = False

        # ALLNS bit (only applies if SAU is disabled: ENABLE=0)
        # 0 = memory is secure and non-secure-callable
        # 1 = memory is non-secure
        self.ALLNS: bool = False

        # Number of SAU regions
        self.SAU_TYPE: int = 0

        # Setup helper variables for configuration writes
        # SAU_RNR
        self.current_sau_number: int | None = None
        # SAU_RBAR
        self.current_sau_start: int | None = None
        # SAU_RLAR (contains end address and attribute)
        self.current_sau_end: int | None = None
        self.current_sau_attr: int | None = None

    def get_region_constructor(self) -> type[SAURegion]:
        return SAURegion

    def config_write(self, address: int, value: int):
        if address == 0xE000EDD0:
            # SAU_CTRL:
            #   bits [31:2] are reserved,
            #   bit [1] is ALLNS
            #   bit [0] is ENABLE
            self.ENABLE = bool(value & 0b1)
            self.ALLNS = bool((value & 0b10) >> 1)
            logger.info(f"SAU->CTRL write detected: 0x{value:08x} -> ENABLE={self.ENABLE}, ALLNS={self.ALLNS}")
        elif address == 0xE000EDD0 + 0x4:
            # Number of SAU regions
            self.SAU_TYPE = value
            # TODO: check if this check is actually enforced
            logger.info(f"SAU->TYPE write detected: 0x{value:08x} -> number_of_regions={self.SAU_TYPE}")
        elif address == 0xE000EDD0 + 0x8:
            self.current_sau_number = value
            logger.info(f"SAU->RNR  write detected: 0x{value:08x} -> region_number={self.current_sau_number}")
        elif address == 0xE000EDD0 + 0xC:
            # SAU_RBAR:
            #   bits [31:5] is start address,
            #   bits [4:0] are reserved
            self.current_sau_start = value & 0xFFFFFFE0
            logger.info(f"SAU->RBAR write detected: 0x{value:08x} -> start=0x{self.current_sau_start:X}")
        elif address == 0xE000EDD0 + 0x10:
            # SAU_RLAR:
            #   bits [31:5] is end address,
            #   bits [4:2] are reserved,
            #   bit [1] is non-secure-callable
            #   bit [0] is ENABLE
            self.current_sau_end = value & 0xFFFFFFE0 | 0b11111
            self.current_sau_attr = (value & 0b10) >> 1
            sau_enable = value & 0b1
            logger.info(f"SAU->RLAR write detected: 0x{value:08x} -> end=0x{self.current_sau_end:X}, attr={self.current_sau_attr}, enable={sau_enable}")
            if sau_enable:
                self.create_region()
        elif address == 0xE000EDD0 + 0x14:
            logger.info(f"SAU->SFSR write detected: 0x{value:08x}")
            # TODO: check what SFSR is used for
        elif address == 0xE000EDD0 + 0x18:
            logger.info(f"SAU->SFAR write detected: 0x{value:08x}")
            # TODO: check what SFAR is used for
        else:
            # This should not happen
            logger.warning(f"Unknown SAU register write detected at 0x{address:08x}: 0x{value:08x}")

    def create_region(self):
        # We should have all required values, check to make sure
        if self.current_sau_number is None or self.current_sau_start is None or self.current_sau_end is None or self.current_sau_attr is None:
            logger.error("Incomplete SAU region configuration")
            return

        region = SAURegion(
            region_number=self.current_sau_number,
            start_address=self.current_sau_start,
            end_address=self.current_sau_end,
            security_state=SecurityState.NONSECURE if self.current_sau_attr == 0 else SecurityState.NONSECURE_CALLABLE,
            is_exempted=False,
        )
        self.add_region(region)
        logger.debug(f"Configured SAU region: {region}")

        # We shouldn't explicitly reset the current values, they will be overwritten
        # If they are not overwritten, the previous values will be used again

    def __repr__(self) -> str:
        return f"""SAU(
    CTRL_ENABLE={self.ENABLE},
    TYPE={self.SAU_TYPE},
    regions=[
        {",\n\t".join(repr(region) for region in self.regions)}
    ]
)"""


@overload
def _nested_attribution_check(
    address: ast.BV,
    regions: Sequence[FlattenedRegion],
    match: Callable[[FlattenedRegion], int | ast.BV],
    default: int | ast.BV,
) -> ast.BV: ...


@overload
def _nested_attribution_check(
    address: ast.BV,
    regions: Sequence[FlattenedRegion],
    match: Callable[[FlattenedRegion], bool | ast.Bool],
    default: bool | ast.Bool,
) -> ast.Bool: ...


def _nested_attribution_check(address, regions, match, default):
    region = regions[0]
    return claripy.If(
        claripy.And(
            # Both inclusive, see ARMv8-M Architecture Reference Manual: R_KRSC
            region.start_address <= address,
            address <= region.end_address,
        ),
        # If address is in this region, return the result of the match function
        match(region),
        _nested_attribution_check(address, regions[1:], match, default)
        if len(regions) > 1
        # If no region matches, return default value
        else default,
    )


class FullAttributionUnit:
    def __init__(self, idau: IDAU, sau: SAU):
        self.idau: IDAU = idau
        self.sau: SAU = sau

    def get_tt_response(
        self,
        address: ast.BV,
        current_security: ProcessorSecurityState,
        current_privilege: ProcessorPrivilegeLevel,
        *,
        a_flag: bool,
        t_flag: bool,
    ) -> ast.BV:
        """ """

        regions = self.get_flattened_regions()
        idau_region_nr = _nested_attribution_check(
            address,
            regions,
            lambda r: claripy.If(
                r.idau_region_number == -1,
                claripy.BVV(0, 8),
                r.idau_region_number,
            ),
            claripy.BVV(0, 8),
        )
        idau_region_valid = _nested_attribution_check(
            address,
            regions,
            lambda r: r.idau_region_number != -1,
            claripy.BoolV(False),
        )

        sau_region_nr = _nested_attribution_check(
            address,
            regions,
            lambda r: claripy.If(r.sau_region_number == -1, claripy.BVV(0, 8), r.sau_region_number),
            claripy.BVV(0, 8),
        )
        sau_region_valid = _nested_attribution_check(
            address,
            regions,
            lambda r: r.sau_region_number != -1,
            claripy.BoolV(False),
        )

        secure = _nested_attribution_check(
            address,
            regions,
            lambda r: r.security_state in [SecurityState.SECURE, SecurityState.NONSECURE_CALLABLE],
            claripy.BoolV(True),  # it shouldn't matter what default is here, as all address space should be covered
        )

        # MPU =====================================================================================
        # TODO: implement the MPU

        # If caller is unprivileged and A-flag is not set, this is RAZ
        # If multiple MPU regions match, this is RAZ
        # If T-flag is set, return permissions for unprivileged access
        # Otherwise, return permissions for current privilege level
        readable = claripy.BoolV(True)  # noqa

        # If caller is unprivileged and A-flag is not set, this is RAZ
        # If multiple MPU regions match, this is RAZ
        # If T-flag is set, return permissions for unprivileged access
        # Otherwise, return permissions for current privilege level
        readwritable = claripy.BoolV(True)  # noqa

        # Non-secure readable. Equal to R AND NOT S.
        # This field is only valid if the variant of the TT group of instructions was executed from
        # Secure state and the R field is valid.
        nonsecure_readable = claripy.If(
            current_security == ProcessorSecurityState.SECURE,
            claripy.And(readable, claripy.Not(secure)),
            claripy.BoolV(False),  # noqa
        )

        # Non-secure read and writable. Equal to RW AND NOT S.
        # This field is only valid if the variant of the TT group of instructions was executed from
        # Secure state and the RW field is valid.
        nonsecure_readwritable = claripy.If(
            current_security == ProcessorSecurityState.SECURE,
            claripy.And(readwritable, claripy.Not(secure)),
            claripy.BoolV(False),  # noqa
        )

        # Should be set to 0 if any of the following are true:
        #    MPU is not implemented,
        # ✅️ MPU_CTRL.ENABLE is 0,
        # ✅️ address does not match any enabled MPU regions,
        # ✅️ address matches multiple enabled MPU regions,
        # ✅️ the TT/TTT without A-flag was executed from unprivileged mode
        mpu_region_valid = claripy.BoolV(False)  # noqa

        mpu_region = claripy.BVV(0, 8)  # noqa

        real_mpu_region = claripy.If(
            mpu_region_valid,
            mpu_region,
            claripy.BVV(0, 8),
        )

        response = TTResponse(
            idau_region_nr,
            idau_region_valid,
            secure,
            nonsecure_readwritable,
            nonsecure_readable,
            readwritable,
            readable,
            sau_region_valid,
            mpu_region_valid,
            sau_region_nr,
            real_mpu_region,
        )

        return response.get_full_bv()

    def get_flattened_regions(self) -> Sequence[FlattenedRegion]:
        idau_regions = self.idau.get_flattened_regions()
        sau_regions = self.sau.get_flattened_regions()

        idau_str = "Flattened IDAU regions:\n"
        for region in idau_regions:
            idau_str += f"\t{region}\n"
        logger.debug(idau_str)

        sau_str = "Flattened SAU regions:\n"
        for region in sau_regions:
            sau_str += f"\t{region}\n"
        logger.debug(sau_str)

        idau_i, sau_i = 0, 0
        curr_p = 0

        regions: list[FlattenedRegion] = []

        while idau_i < len(idau_regions) and sau_i < len(sau_regions):
            curr_idau_reg = idau_regions[idau_i]
            curr_sau_reg = sau_regions[sau_i]

            # Calculate security state
            idau_sec = curr_idau_reg.security_state
            sau_sec = curr_sau_reg.security_state
            idau_region_nr = curr_idau_reg.region_number
            sau_region_nr = curr_sau_reg.region_number

            if curr_idau_reg.is_exempted:
                sec = idau_sec
                idau_region_nr = -1
                sau_region_nr = -1

            elif idau_sec == SecurityState.SECURE or sau_sec == SecurityState.SECURE:
                sec = SecurityState.SECURE
            elif idau_sec == SecurityState.NONSECURE_CALLABLE or sau_sec == SecurityState.NONSECURE_CALLABLE:
                sec = SecurityState.NONSECURE_CALLABLE
            else:
                sec = SecurityState.NONSECURE

            # Determine next split point
            if curr_idau_reg.end_address == curr_sau_reg.end_address:
                next_p = curr_idau_reg.end_address
                idau_i += 1
                sau_i += 1
            elif curr_idau_reg.end_address < curr_sau_reg.end_address:
                idau_i += 1
                next_p = curr_idau_reg.end_address
            else:
                sau_i += 1
                next_p = curr_sau_reg.end_address

            regions.append(
                FlattenedRegion(
                    sau_region_number=sau_region_nr,
                    idau_region_number=idau_region_nr,
                    start_address=curr_p,
                    end_address=next_p,
                    security_state=sec,
                ),
            )

            curr_p = next_p + 1

        return merge_adjacent_regions(regions)

    def get_enclave_ranges(self) -> list[tuple[int, int]]:
        """Get address ranges that are Secure and Non-secure-callable"""
        flattened_regions = self.get_flattened_regions()

        regions = [(r.start_address, r.end_address) for r in flattened_regions if r.security_state == SecurityState.NONSECURE_CALLABLE or r.security_state == SecurityState.SECURE]

        # TODO: clean this up by reusing merge_adjacent_regions
        # Merge adjacent/overlapping regions
        merged_regions: list[tuple[int, int]] = []
        for region in regions:
            if len(merged_regions) == 0:
                merged_regions.append(region)
            else:
                last_region = merged_regions[-1]
                if last_region[1] + 1 == region[0]:
                    merged_region = (last_region[0], max(last_region[1], region[1]))
                    merged_regions[-1] = merged_region
                else:
                    merged_regions.append(region)
        return merged_regions

    def get_nsc_ranges(self) -> list[tuple[int, int]]:
        """Get address ranges that are Non-secure-callable"""
        flattened_regions = self.get_flattened_regions()

        regions = [(r.start_address, r.end_address) for r in flattened_regions if r.security_state == SecurityState.NONSECURE_CALLABLE]

        # TODO: clean this up by reusing merge_adjacent_regions
        # Merge adjacent/overlapping regions
        merged_regions: list[tuple[int, int]] = []
        for region in regions:
            if len(merged_regions) == 0:
                merged_regions.append(region)
            else:
                last_region = merged_regions[-1]
                if last_region[1] + 1 == region[0]:
                    merged_region = (last_region[0], max(last_region[1], region[1]))
                    merged_regions[-1] = merged_region
                else:
                    merged_regions.append(region)
        return merged_regions


@dataclass
class TTResponse:
    # Docs from ARMv8-M Reference Manual: D1.2.269 TT_RESP, Test Target Response Payload

    # IDAU region number. Indicates the IDAU region number containing the target address.
    # This field is zero if IRVALID is zero
    idau_region: ast.BV

    # IREGION valid flag. For a Secure request, indicates the validity of the IREGION field.
    # The possible values of this bit are:
    #   0 -> IREGION content not valid.
    #   1 -> IREGION content valid.
    # This bit is always zero if the IDAU cannot provide a region number, the address is exempt from
    # security attribution, or if the requesting TT or TTT variant was executed from the Non-secure
    # state.
    idau_region_valid: ast.Bool

    # Security. For a Secure request, indicates the Security attribute of the target address.
    # The possible values of this bit are:
    #   0 -> Target address is Non-secure.
    #   1 -> Target address is Secure.
    # This bit is always zero if the requesting TT or TTT instruction was executed from the
    # Non-secure state
    secure: ast.Bool

    # Non-secure read and writable. Equal to RW AND NOT S.
    # This field is only valid if the variant of the TT group of instructions was executed from
    # Secure state and the RW field is valid.
    nonsecure_readwrite_ok: ast.Bool

    # Non-secure readable. Equal to R AND NOT S.
    # This field is only valid if the variant of the TT group of instructions was executed from
    # Secure state and the R field is valid.
    nonsecure_read_ok: ast.Bool

    # Read and writable.
    # Set to 1 if the address specified by the TT instruction variant can be read and written
    # according to the permissions of the selected MPU when operating in the privilege level for the
    # selected mode and selected Security state. For TTT and TTAT, this field returns the
    # permissions for unprivileged access, regardless of whether the selected mode and state is
    # privileged or unprivileged. This field is invalid and RAZ if the TT instruction was executed
    # from an unprivileged mode and the A flag was not specified. This field is also RAZ if the
    # address matches multiple MPU regions.
    readwrite_ok: ast.Bool

    # Readable.
    # Read accessibility. Set to 1 if the address specified by the TT instruction variant can be
    # read according to the permissions of the selected MPU when operating in the privilege level
    # for the selected mode and selected Security state. For TTT and TTAT, this field returns the
    # permissions for unprivileged access, regardless of whether the selected mode and state is
    # privileged or unprivileged. This field is invalid and RAZ if the TT instruction was executed
    # from an unprivileged mode and the A flag was not specified. This field is also RAZ if the
    # address matches multiple MPU regions.
    read_ok: ast.Bool

    # SREGION valid flag. For a Secure request indicates validity of the SREGION field.
    # The possible values of this bit are:
    #   0 -> SREGION content not valid.
    #   1 -> SREGION content valid.
    # The SREGION field is invalid if any of the following are true:
    #   SAU_CTRL.ENABLE is set to zero.
    #   The address specified by the TT instruction variant field does not match any enabled SAU
    #       regions.
    #   The address specified matches multiple enabled SAU regions.
    #   The address specified by the TT instruction variant is exempt from the Secure memory
    #       attribution.
    #   The TT or TTT instruction variant was executed from the Non-secure state or the Security
    #       Extension is not implemented.
    # The TTA and TTAT instruction variants are UNDEFINED when executed from Non-secure state.
    sau_region_valid: ast.Bool

    # MREGION valid flag. Indicates validity of the MREGION field.
    # The possible values of this bit are:
    #   0 -> MREGION content not valid.
    #   1 -> MREGION content valid.
    # The MREGION field is invalid if any of the following is true:
    #   The MPU is not implemented or MPU_CTRL.ENABLE is set to zero.
    #   The address specified by the TT instruction variant does not match any enabled MPU regions.
    #   The address matched multiple MPU regions.
    #   The TT or TTT instruction variants, without the A flag specified, were executed from an
    #       unprivileged mode.
    # The TTA and TTAT instructions are UNDEFINED when executed from Non-secure state
    mpu_region_valid: ast.Bool

    # SAU region number. Holds the SAU region that the address maps to.
    # This field is only valid if the instruction was executed from Secure state.
    # This field is zero if SRVALID is 0.
    sau_region: ast.BV

    # MPU region number. Holds the MPU region that the address maps to.
    # This field is zero if MRVALID is 0.
    mpu_region: ast.BV

    def get_full_bv(self) -> ast.BV:
        return claripy.Concat(
            self.idau_region,
            claripy.If(self.idau_region_valid, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.secure, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.nonsecure_readwrite_ok, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.nonsecure_read_ok, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.readwrite_ok, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.read_ok, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.sau_region_valid, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(self.mpu_region_valid, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            self.sau_region,
            self.mpu_region,
        )

    def __repr__(self) -> str:
        return f"""TTResponse(
    idau_region={self.idau_region},
    idau_region_valid={self.idau_region_valid},
    secure={self.secure},
    nonsecure_readwrite_ok={self.nonsecure_readwrite_ok},
    nonsecure_read_ok={self.nonsecure_read_ok},
    readwrite_ok={self.readwrite_ok},
    read_ok={self.read_ok},
    sau_region_valid={self.sau_region_valid},
    mpu_region_valid={self.mpu_region_valid},
    sau_region={self.sau_region},
    mpu_region={self.mpu_region},
)"""
