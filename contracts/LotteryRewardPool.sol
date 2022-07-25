pragma solidity >=0.8.0;

import './MasterGamer.sol';

contract LotteryRewardPool is AccessControl {
    using SafeERC20 for IERC20;

    MasterGamer public chef;
    address public adminAddress;
    address public receiver;
    IERC20 public lptoken;
    IERC20 public xp;

    constructor(
        MasterGamer _chef,
        IERC20 _xp,
        address _admin,
        address _receiver
    ) public {
        chef = _chef;
        xp = _xp;
        adminAddress = _admin;
        receiver = _receiver;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(DEV_ROLE, _admin);
    }

    bytes32 public DEV_ROLE = keccak256("DEV_ROLE");

    event StartFarming(address indexed user, uint256 indexed pid);
    event Harvest(address indexed user, uint256 indexed pid);
    event EmergencyWithdraw(address indexed user, uint256 amount);


    function startFarming(uint256 _pid, IERC20 _lptoken, uint256 _amount) external onlyRole(DEV_ROLE) {
        _lptoken.safeApprove(address(chef), _amount);
        chef.deposit(_pid, _amount);
        emit StartFarming(msg.sender, _pid);
    }

    function harvest(uint256 _pid) external onlyRole(DEV_ROLE) {
        chef.deposit(_pid, 0);
        uint256 balance = xp.balanceOf(address(this));
        xp.safeTransfer(receiver, balance);
        emit Harvest(msg.sender, _pid);
    }

    function setReceiver(address _receiver) external onlyRole(DEV_ROLE) {
        receiver = _receiver;
    }

    function  pendingReward(uint256 _pid) external view returns (uint256) {
        return chef.pendingXp(_pid, address(this));
    }

    // EMERGENCY ONLY.
    function emergencyWithdraw(IERC20 _token, uint256 _amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        xp.safeTransfer(address(msg.sender), _amount);
        emit EmergencyWithdraw(msg.sender, _amount);
    }

    function setAdmin(address _admin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(DEV_ROLE, adminAddress);
        adminAddress = _admin;
        _grantRole(DEV_ROLE, _admin);
    }

}
