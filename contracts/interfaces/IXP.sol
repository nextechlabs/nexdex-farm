//SPDX-License-Identifier: Unlicensed

pragma solidity >=0.8.12;

interface IXP {

    function MINTER_ROLE() external view returns(bytes32);

    function LOCK_ROLE() external view returns(bytes32);

    function EARLY_UNLOCK_ROLE() external view returns(bytes32);

    function unlockingStartDate() external view returns(uint);

    function unlockingEndDate() external view returns(uint);

    function lockOf(address account) external view returns(uint);

    function unlockableOf(address account) external view returns(uint unlockable);

    function lock(address account, uint amount) external;

    function unlock(uint amount) external;

    function earlyUnlock(address account, uint amount) external;

    function mint(address account, uint amount) external;

}
