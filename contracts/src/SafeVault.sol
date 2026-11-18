// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SafeVault
/// @notice Minimal, non-upgradeable ETH vault used as the release artifact of the
///         multi-chain release engine.
/// @dev Design rules:
///      - The owner is an explicit constructor argument. Under CREATE2 the constructor's
///        `msg.sender` is the deterministic deployer proxy, not the deployer key, and the
///        deployer key should never be the admin anyway (separation of duties).
///      - The owner can pause deposits but can never block withdrawals or move user funds.
///      - Ownership transfer is two-step so a typo cannot brick administration.
contract SafeVault {
    string public constant VERSION = "1.0.0";

    address public owner;
    address public pendingOwner;
    bool public paused;
    uint256 public totalDeposits;
    mapping(address account => uint256 amount) public balanceOf;

    uint256 private _locked = 1;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error Unauthorized(address caller);
    error ZeroAddress();
    error ZeroAmount();
    error DepositsPaused();
    error InsufficientBalance(uint256 requested, uint256 available);
    error Reentrancy();
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    receive() external payable {
        _deposit(msg.sender, msg.value);
    }

    function deposit() external payable {
        _deposit(msg.sender, msg.value);
    }

    /// @notice Withdraw `amount` wei. Never pausable: users must always be able to exit.
    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 available = balanceOf[msg.sender];
        if (amount > available) revert InsufficientBalance(amount, available);

        // Effects before interaction. `totalDeposits >= balanceOf[account]` is an
        // invariant (see SafeVault.invariant.t.sol), so neither subtraction can underflow.
        unchecked {
            balanceOf[msg.sender] = available - amount;
            totalDeposits -= amount;
        }
        emit Withdrawn(msg.sender, amount);

        // The only state write after this call is the `nonReentrant` lock release; all
        // accounting is final before the call (CEI). See test_Withdraw_ReentrancyIsBlocked.
        // forge-lint: disable-next-line(reentrancy-eth)
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Start a two-step ownership transfer; `newOwner` must call `acceptOwnership`.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        pendingOwner = address(0);
        emit OwnershipTransferStarted(owner, address(0));
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized(msg.sender);
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    function _deposit(address account, uint256 amount) private {
        if (paused) revert DepositsPaused();
        if (amount == 0) revert ZeroAmount();
        balanceOf[account] += amount;
        totalDeposits += amount;
        emit Deposited(account, amount);
    }
}
