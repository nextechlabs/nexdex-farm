pragma solidity >=0.8.12;

import '@openzeppelin/contracts/security/ReentrancyGuard.sol';
import "@thenexlabs/nex-lib/contracts/access/AccessControl.sol";
import "@thenexlabs/nex-lib/contracts/token/ERC20/ERC20.sol";
import "./interfaces/IXP.sol";


// Xp with Governance & lock up.
contract Xp is IXP, ERC20, AccessControl, ReentrancyGuard{

    constructor(uint unlockingStartDate_, uint unlockingEndDate_, uint cap_) ERC20('Experience Token', 'XP') {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(LOCK_ROLE, msg.sender);
        unlockingStartDate = unlockingStartDate_;
        unlockingEndDate = unlockingEndDate_;
        _cap = cap_;

        _excludedFromAntiWhale[msg.sender] = true;
        _excludedFromAntiWhale[address(0)] = true;
        _excludedFromAntiWhale[address(this)] = true;
    }


    uint256 private _cap;

    bytes32 public MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public LOCK_ROLE = keccak256("LOCK_ROLE");
    bytes32 public EARLY_UNLOCK_ROLE = keccak256("EARLY_UNLOCK_ROLE");

    uint public unlockingStartDate;
    uint public unlockingEndDate;

    uint private _totalLocked;

    mapping(address => uint) _lockups;

    // Max transfer amount rate in basis points. Default is 10% of total
    // supply, and it can't be less than 0.5% of the supply. 10000 = 100%
    uint16 public maxTransferAmountRate = 1000;

    // Addresses that are excluded from anti-whale checking.
    mapping(address => bool) private _excludedFromAntiWhale;

    // Events.
    event MaxTransferAmountRateUpdated(uint256 previousRate, uint256 newRate);
    event Lock(address indexed to, uint256 value);
    event Unlock(address indexed to, uint256 value);

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual override
    antiWhale(sender, recipient, amount) {
        super._transfer(sender, recipient, amount);
        _moveDelegates(_delegates[sender], _delegates[recipient], amount);
    }

    function lockOf(address account) external view returns(uint) {
        return _lockups[account];
    }

    function unlockableOf(address account) public view returns(uint unlockable) {

        if(block.timestamp < unlockingStartDate) {
          return 0;
        }

        uint timeSince = block.timestamp - unlockingStartDate;
        uint totalLockTime = unlockingEndDate - unlockingStartDate;
        uint timeUnlocking = timeSince <= totalLockTime ? timeSince : totalLockTime;

        unlockable = ((timeUnlocking * _lockups[account]) / totalLockTime);// + lockInfo.owed - lockInfo.debt;//
    }

    function lock(address _holder, uint amount) external onlyRole(LOCK_ROLE) {

        require(_holder != address(0), "Cannot lock to the zero address");

        _transfer(_holder, address(this), amount);

        /* uint unlockableBefore = unlockableOf(_holder);// */

        _lockups[_holder] += amount;
        _totalLocked += amount;

        /* uint unlockableAfter = unlockableOf(_holder);//

        uint debt = unlockableAfter - unlockableBefore;//

        lockInfo.debt += debt;// */
        emit Lock(_holder, amount);
    }

    function unlock(uint amount) external nonReentrant{

        uint unlockableBefore = unlockableOf(msg.sender);

        // Make sure they aren't trying to unlock more than they have unlockable.
        if (amount > unlockableBefore) {
          amount = unlockableBefore;
        }

        /* uint targetUnlockable = unlockableBefore - amount;// */

        _transfer(address(this), msg.sender, amount);

        _lockups[msg.sender] -= amount;

        /* uint unlockableAfter = unlockableOf(msg.sender);//

        uint owed = targetUnlockable - unlockableAfter;//

        lockInfo.owed += owed;// */
        emit Unlock(msg.sender, amount);
    }

    function earlyUnlock(address account, uint amount) external onlyRole(EARLY_UNLOCK_ROLE) {

        uint locked = _lockups[account];

        require(locked>=amount, "Insufficient locked balance");

        _transfer(address(this), account, amount);

        /* uint unlockableBefore = unlockableOf(account);// */

        _lockups[account] -= amount;

        /* uint unlockableAfter = unlockableOf(account);//

        uint owed = unlockableAfter - unlockableBefore;//

        lockInfo.owed += owed;// */
    }

    // This function is for dev address migrate all balance to a multi sig address
    function transferAll(address _to) public {
        _lockups[_to] = _lockups[_to] + _lockups[msg.sender];

        _lockups[msg.sender] = 0;

        _transfer(msg.sender, _to, balanceOf(msg.sender));
    }

    /**
     * @dev Ensures that the anti-whale rules are enforced.
     */
    modifier antiWhale(address sender, address recipient, uint256 amount) {
        if (maxTransferAmount() > 0) {
            if (
                _excludedFromAntiWhale[sender] == false
                && _excludedFromAntiWhale[recipient] == false
            ) {
                require(amount <= maxTransferAmount(), "antiWhale: Transfer amount exceeds the maxTransferAmount");
            }
        }
        _;
    }

    /**
     * @dev Update the max transfer amount rate.
     */
    function updateMaxTransferAmountRate(uint16 _maxTransferAmountRate) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_maxTransferAmountRate <= 10000, "updateMaxTransferAmountRate: Max transfer amount rate must not exceed the maximum rate.");
        require(_maxTransferAmountRate >= 50, "updateMaxTransferAmountRate: Max transfer amount rate must be more than 0.005.");
        emit MaxTransferAmountRateUpdated(maxTransferAmountRate, _maxTransferAmountRate);
        maxTransferAmountRate = _maxTransferAmountRate;
    }

    /**
     * @dev Calculates the max transfer amount.
     */
    function maxTransferAmount() public view returns (uint256) {
        return totalSupply() * maxTransferAmountRate / 10000;
    }

    /**
     * @dev Sets an address as excluded or not from the anti-whale checking.
     */
    function setExcludedFromAntiWhale(address _account, bool _excluded) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _excludedFromAntiWhale[_account] = _excluded;
    }

    function unlockedSupply() public view returns (uint256) {
        return totalSupply() - _totalLocked;
    }

    function lockedSupply() public view returns (uint256) {
        return _totalLocked;
    }

    // Xp below

    /**
     * @dev Returns the cap on the token's total supply.
     */
    function cap() public view returns (uint256) {
        return _cap;
    }

    /**
     * @dev Updates the total cap.
     */
    function capUpdate(uint256 _newCap) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _cap = _newCap;
    }

    /**
     * @dev See {ERC20-_beforeTokenTransfer}.
     *
     * Requirements:
     *
     * - minted tokens must not cause the total supply to go over the cap.
     */
     function _beforeTokenTransfer(
         address from,
         address to,
         uint256 amount
     ) internal virtual override {
         super._beforeTokenTransfer(from, to, amount);

         if (from == address(0)) {
             // When minting tokens
             require(
                 (totalSupply() + amount) <= _cap,
                 "ERC20Capped: supply cap exceeded"
             );
         }
     }

    /// @notice Creates `_amount` token to `_to`. Must only be called by the owner (MasterGamer).
    function mint(address _to, uint256 _amount) external onlyRole(MINTER_ROLE) {
        _mint(_to, _amount);
        _moveDelegates(address(0), _delegates[_to], _amount);
    }

    // Copied and modified from YAM code:
    // https://github.com/yam-finance/yam-protocol/blob/master/contracts/token/YAMGovernanceStorage.sol
    // https://github.com/yam-finance/yam-protocol/blob/master/contracts/token/YAMGovernance.sol
    // Which is copied and modified from COMPOUND:
    // https://github.com/compound-finance/compound-protocol/blob/master/contracts/Governance/Comp.sol

    /// @notice A record of each accounts delegate
    mapping (address => address) internal _delegates;

    /// @notice A checkpoint for marking number of votes from a given block
    struct Checkpoint {
        uint32 fromBlock;
        uint256 votes;
    }

    /// @notice A record of votes checkpoints for each account, by index
    mapping (address => mapping (uint32 => Checkpoint)) public checkpoints;

    /// @notice The number of checkpoints for each account
    mapping (address => uint32) public numCheckpoints;

    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

    /// @notice The EIP-712 typehash for the delegation struct used by the contract
    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

    /// @notice A record of states for signing / validating signatures
    mapping (address => uint) public nonces;

      /// @notice An event thats emitted when an account changes its delegate
    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);

    /// @notice An event thats emitted when a delegate account's vote balance changes
    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);

    /**
     * @notice Delegate votes from `msg.sender` to `delegatee`
     * @param delegator The address to get delegatee for
     */
    function delegates(address delegator)
        external
        view
        returns (address)
    {
        return _delegates[delegator];
    }

   /**
    * @notice Delegate votes from `msg.sender` to `delegatee`
    * @param delegatee The address to delegate votes to
    */
    function delegate(address delegatee) external {
        return _delegate(msg.sender, delegatee);
    }

    /**
     * @notice Delegates votes from signatory to `delegatee`
     * @param delegatee The address to delegate votes to
     * @param nonce The contract state required to match the signature
     * @param expiry The time at which to expire the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function delegateBySig(
        address delegatee,
        uint nonce,
        uint expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name())),
                getChainId(),
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                DELEGATION_TYPEHASH,
                delegatee,
                nonce,
                expiry
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                structHash
            )
        );

        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "XP::delegateBySig: invalid signature");
        require(nonce == nonces[signatory]++, "XP::delegateBySig: invalid nonce");
        require(block.timestamp <= expiry, "XP::delegateBySig: signature expired");
        return _delegate(signatory, delegatee);
    }

    /**
     * @notice Gets the current votes balance for `account`
     * @param account The address to get votes balance
     * @return The number of current votes for `account`
     */
    function getCurrentVotes(address account)
        external
        view
        returns (uint256)
    {
        uint32 nCheckpoints = numCheckpoints[account];
        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;
    }

    /**
     * @notice Determine the prior number of votes for an account as of a block number
     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.
     * @param account The address of the account to check
     * @param blockNumber The block number to get the vote balance at
     * @return The number of votes the account had as of the given block
     */
    function getPriorVotes(address account, uint blockNumber)
        external
        view
        returns (uint256)
    {
        require(blockNumber < block.number, "XP::getPriorVotes: not yet determined");

        uint32 nCheckpoints = numCheckpoints[account];
        if (nCheckpoints == 0) {
            return 0;
        }

        // First check most recent balance
        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[account][nCheckpoints - 1].votes;
        }

        // Next check implicit zero balance
        if (checkpoints[account][0].fromBlock > blockNumber) {
            return 0;
        }

        uint32 lower = 0;
        uint32 upper = nCheckpoints - 1;
        while (upper > lower) {
            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }
        return checkpoints[account][lower].votes;
    }

    function _delegate(address delegator, address delegatee)
        internal
    {
        address currentDelegate = _delegates[delegator];
        uint256 delegatorBalance = balanceOf(delegator); // balance of underlying XPs (not scaled);
        _delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, currentDelegate, delegatee);

        _moveDelegates(currentDelegate, delegatee, delegatorBalance);
    }

    function _moveDelegates(address srcRep, address dstRep, uint256 amount) internal {
        if (srcRep != dstRep && amount > 0) {
            if (srcRep != address(0)) {
                // decrease old representative
                uint32 srcRepNum = numCheckpoints[srcRep];
                uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
                uint256 srcRepNew = srcRepOld - amount;
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                // increase new representative
                uint32 dstRepNum = numCheckpoints[dstRep];
                uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
                uint256 dstRepNew = dstRepOld + amount;
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }

    function _writeCheckpoint(
        address delegatee,
        uint32 nCheckpoints,
        uint256 oldVotes,
        uint256 newVotes
    )
        internal
    {
        uint32 blockNumber = safe32(block.number, "XP::_writeCheckpoint: block number exceeds 32 bits");

        if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {
            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
        } else {
            checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);
            numCheckpoints[delegatee] = nCheckpoints + 1;
        }

        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

    function safe32(uint n, string memory errorMessage) internal pure returns (uint32) {
        require(n < 2**32, errorMessage);
        return uint32(n);
    }

    function getChainId() internal view returns (uint) {
        uint256 chainId;
        assembly { chainId := chainid() }
        return chainId;
    }

    function transferOwnership(address newOwner) public override onlyRole(DEFAULT_ADMIN_ROLE){
      _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
      _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
    }
}
