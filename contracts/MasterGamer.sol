pragma solidity >=0.8.0;

import '@thenexlabs/nex-lib/contracts/math/SafeMath.sol';
import "@thenexlabs/nex-lib/contracts/token/ERC20/IERC20.sol";
import "@thenexlabs/nex-lib/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "./Xp.sol";
import "./BoostBar.sol";

// import "@nomiclabs/buidler/console.sol";

interface IMigratorGamer {
  // Perform LP token migration from legacy NexDex to UpgradedNexDex.
  // Take the current LP token address and return the new LP token address.
  // Migrator should have full access to the caller's LP token.
  // Return the new LP token address.
  //
  // XXX Migrator must have allowance access to NexDex LP tokens.
  // XpSwap must mint EXACTLY the same amount of NexDex LP tokens or
  // else something bad will happen. Traditional PanxpSwap does not
  // do that so be careful!
  function migrate(IERC20 token) external returns (IERC20);
}

// MasterGamer is the master of Xp. He can make Xp and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once XP is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract MasterGamer is AccessControl, ReentrancyGuard {
  using SafeMath for uint256;
  using SafeERC20 for IERC20;

  // Info of each user.
  struct UserInfo {
    uint256 amount;     // How many LP tokens the user has provided.
    uint256 rewardDebt; // Reward debt. See explanation below.
    //
    // We do some fancy math here. Basically, any point in time, the amount of XP
    // entitled to a user but is pending to be distributed is:
    //
    //   pending reward = (user.amount * pool.accXpPerShare) - user.rewardDebt
    //
    // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
    //   1. The pool's `accXpPerShare` (and `lastRewardBlock`) gets updated.
    //   2. User receives the pending reward sent to his/her address.
    //   3. User's `amount` gets updated.
    //   4. User's `rewardDebt` gets updated.
  }

  // Info of each pool.
  struct PoolInfo {
    IERC20 lpToken;           // Address of LP token contract.
    uint256 allocPoint;       // How many allocation points assigned to this pool. XPs to distribute per block.
    uint256 lastRewardBlock;  // Last block number that XPs distribution occurs.
    uint256 accXpPerShare; // Accumulated XPs per share, times 1e12. See below.
  }

  // The XP TOKEN!
  Xp public xp;
  // The BOOST TOKEN!
  BoostBar public boost;
  // Dev address.
  address public devaddr;
  // XP tokens created per block.
  uint256 public xpPerBlock;
  // Bonus muliplier for early xp makers.
  uint256 public BONUS_MULTIPLIER = 1;
  // The migrator contract. It has a lot of power. Can only be set through governance (owner).
  IMigratorGamer public migrator;

  // Info of each pool.
  PoolInfo[] public poolInfo;
  // Info of each user that stakes LP tokens.
  mapping (uint256 => mapping (address => UserInfo)) public userInfo;
  // Total allocation points. Must be the sum of all allocation points in all pools.
  uint256 public totalAllocPoint = 0;
  // The block number when XP mining starts.
  uint256 public startBlock;

  event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
  event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
  event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);

  constructor(
    Xp _xp,
    BoostBar _boost,
    address _devaddr,
    uint256 _xpPerBlock,
    uint256 _startBlock
  ) public {
    xp = _xp;
    boost = _boost;
    devaddr = _devaddr;
    xpPerBlock = _xpPerBlock;
    startBlock = _startBlock;

    // staking pool
    poolInfo.push(PoolInfo({
      lpToken: _xp,
      allocPoint: 1000,
      lastRewardBlock: startBlock,
      accXpPerShare: 0
    }));

    totalAllocPoint = 1000;
    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    _grantRole(DEFAULT_ADMIN_ROLE, devaddr);
  }

  function updateMultiplier(uint256 multiplierNumber) public onlyRole(DEFAULT_ADMIN_ROLE) {
    BONUS_MULTIPLIER = multiplierNumber;
  }

  function poolLength() external view returns (uint256) {
    return poolInfo.length;
  }

  // Add a new lp to the pool. Can only be called by the owner.
  // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.
  function add(uint256 _allocPoint, IERC20 _lpToken, bool _withUpdate) public onlyRole(DEFAULT_ADMIN_ROLE) {
    if (_withUpdate) {
      massUpdatePools();
    }
    uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
    totalAllocPoint = totalAllocPoint.add(_allocPoint);
    poolInfo.push(PoolInfo({
      lpToken: _lpToken,
      allocPoint: _allocPoint,
      lastRewardBlock: lastRewardBlock,
      accXpPerShare: 0
      }));
      updateStakingPool();
    }

    // Update the given pool's XP allocation point. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, bool _withUpdate) public onlyRole(DEFAULT_ADMIN_ROLE) {
      if (_withUpdate) {
        massUpdatePools();
      }
      uint256 prevAllocPoint = poolInfo[_pid].allocPoint;
      poolInfo[_pid].allocPoint = _allocPoint;
      if (prevAllocPoint != _allocPoint) {
        totalAllocPoint = totalAllocPoint.sub(prevAllocPoint).add(_allocPoint);
        updateStakingPool();
      }
    }

    function updateStakingPool() internal {
      uint256 length = poolInfo.length;
      uint256 points = 0;
      for (uint256 pid = 1; pid < length; ++pid) {
        points = points.add(poolInfo[pid].allocPoint);
      }
      if (points != 0) {
        points = points.div(3);
        totalAllocPoint = totalAllocPoint.sub(poolInfo[0].allocPoint).add(points);
        poolInfo[0].allocPoint = points;
      }
    }

    // Set the migrator contract. Can only be called by the owner.
    function setMigrator(IMigratorGamer _migrator) public onlyRole(DEFAULT_ADMIN_ROLE) {
      migrator = _migrator;
    }

    // Migrate lp token to another lp contract. Can be called by anyone. We trust that migrator contract is good.
    function migrate(uint256 _pid) public {
      require(address(migrator) != address(0), "migrate: no migrator");
      PoolInfo storage pool = poolInfo[_pid];
      IERC20 lpToken = pool.lpToken;
      uint256 bal = lpToken.balanceOf(address(this));
      lpToken.safeApprove(address(migrator), bal);
      IERC20 newLpToken = migrator.migrate(lpToken);
      require(bal == newLpToken.balanceOf(address(this)), "migrate: bad");
      pool.lpToken = newLpToken;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
      return _to.sub(_from).mul(BONUS_MULTIPLIER);
    }

    // View function to see pending XPs on frontend.
    function pendingXp(uint256 _pid, address _user) external view returns (uint256) {
      PoolInfo storage pool = poolInfo[_pid];
      UserInfo storage user = userInfo[_pid][_user];
      uint256 accXpPerShare = pool.accXpPerShare;
      uint256 lpSupply = pool.lpToken.balanceOf(address(this));
      if (block.number > pool.lastRewardBlock && lpSupply != 0) {
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 xpReward = multiplier.mul(xpPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        accXpPerShare = accXpPerShare.add(xpReward.mul(1e12).div(lpSupply));
      }
      return user.amount.mul(accXpPerShare).div(1e12).sub(user.rewardDebt);
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
      uint256 length = poolInfo.length;
      for (uint256 pid = 0; pid < length; ++pid) {
        updatePool(pid);
      }
    }


    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
      PoolInfo storage pool = poolInfo[_pid];
      if (block.number <= pool.lastRewardBlock) {
        return;
      }
      uint256 lpSupply = pool.lpToken.balanceOf(address(this));
      if (lpSupply == 0) {
        pool.lastRewardBlock = block.number;
        return;
      }
      uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
      uint256 xpReward = multiplier.mul(xpPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
      xp.mint(address(boost), xpReward);
      xp.mint(devaddr, xpReward.div(10));
      pool.accXpPerShare = pool.accXpPerShare.add(xpReward.mul(1e12).div(lpSupply));
      pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterGamer for XP allocation.
    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {

      require (_pid != 0, 'deposit XP by staking');

      PoolInfo storage pool = poolInfo[_pid];
      UserInfo storage user = userInfo[_pid][msg.sender];
      updatePool(_pid);
      if (user.amount > 0) {
        uint256 pending = user.amount.mul(pool.accXpPerShare).div(1e12).sub(user.rewardDebt);
        if(pending > 0) {
          safeXpTransfer(msg.sender, pending);
        }
      }
      if (_amount > 0) {
        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
        user.amount = user.amount.add(_amount);
      }
      user.rewardDebt = user.amount.mul(pool.accXpPerShare).div(1e12);
      emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from MasterGamer.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {

      require (_pid != 0, 'withdraw XP by unstaking');
      PoolInfo storage pool = poolInfo[_pid];
      UserInfo storage user = userInfo[_pid][msg.sender];
      require(user.amount >= _amount, "withdraw: not good");

      updatePool(_pid);
      uint256 pending = user.amount.mul(pool.accXpPerShare).div(1e12).sub(user.rewardDebt);
      if(pending > 0) {
        safeXpTransfer(msg.sender, pending);
      }
      if(_amount > 0) {
        user.amount = user.amount.sub(_amount);
        pool.lpToken.safeTransfer(address(msg.sender), _amount);
      }
      user.rewardDebt = user.amount.mul(pool.accXpPerShare).div(1e12);
      emit Withdraw(msg.sender, _pid, _amount);
    }

    // Stake XP tokens to MasterGamer
    function enterStaking(uint256 _amount) public {
      PoolInfo storage pool = poolInfo[0];
      UserInfo storage user = userInfo[0][msg.sender];
      updatePool(0);
      if (user.amount > 0) {
        uint256 pending = user.amount.mul(pool.accXpPerShare).div(1e12).sub(user.rewardDebt);
        if(pending > 0) {
          safeXpTransfer(msg.sender, pending);
        }
      }
      if(_amount > 0) {
        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
        user.amount = user.amount.add(_amount);
      }
      user.rewardDebt = user.amount.mul(pool.accXpPerShare).div(1e12);

      boost.mint(msg.sender, _amount);
      emit Deposit(msg.sender, 0, _amount);
    }

    // Withdraw XP tokens from STAKING.
    function leaveStaking(uint256 _amount) public {
      PoolInfo storage pool = poolInfo[0];
      UserInfo storage user = userInfo[0][msg.sender];
      require(user.amount >= _amount, "withdraw: not good");
      updatePool(0);
      uint256 pending = user.amount.mul(pool.accXpPerShare).div(1e12).sub(user.rewardDebt);
      if(pending > 0) {
        safeXpTransfer(msg.sender, pending);
      }
      if(_amount > 0) {
        user.amount = user.amount.sub(_amount);
        pool.lpToken.safeTransfer(address(msg.sender), _amount);
      }
      user.rewardDebt = user.amount.mul(pool.accXpPerShare).div(1e12);

      boost.burn(msg.sender, _amount);
      emit Withdraw(msg.sender, 0, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
      PoolInfo storage pool = poolInfo[_pid];
      UserInfo storage user = userInfo[_pid][msg.sender];
      pool.lpToken.safeTransfer(address(msg.sender), user.amount);
      emit EmergencyWithdraw(msg.sender, _pid, user.amount);
      user.amount = 0;
      user.rewardDebt = 0;
    }

    // Safe xp transfer function, just in case if rounding error causes pool to not have enough XPs.
    function safeXpTransfer(address _to, uint256 _amount) internal {
      boost.safeXpTransfer(_to, _amount);
      xp.lock(_to, _amount*90/100);
    }

    // Update dev address by the previous dev.
    function dev(address _devaddr) public {
      require(msg.sender == devaddr, "dev: wut?");
      devaddr = _devaddr;
    }

    function transferOwnership(address newOwner) public onlyRole(DEFAULT_ADMIN_ROLE){
      _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
      _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
    }
  }
