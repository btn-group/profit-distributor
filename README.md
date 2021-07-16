# Profit distributor
btn.group's profit distributor.

## How it works
* User deposits Buttcoin into this smart contract.
* This smart contract receives profits and distributes to users.

## The three pillars of blockchain
The three pillars refers to blockchain itself but we are attempting to follow the ethos as much as possible.

### 1. Decentralization
This contract has two admin only functions:
1. Change admin.
2. Register receivable profit token.

Had to make registering of receivable profit tokens admin only, as someone could add a tonne of random tokens which would make the the contract unusable due to fees.

### 2. Transparency
All involved smart contracts are publicly viewable and audited by third parties. 
1. Buttcoin balance of contract is publicly viewable.
2. The total raised for each profit cryptocurrency is publicly viewable.
3. The balance for each profit token is publicly viewable.

### 3. Immutability
All tokens involved follow the SNIP-20 standard. The state of the smart contract cannot be changed by users/admin.

## Regarding privacy
We have thought long and hard about this and have decided to make many aspects public. This means that it would be pretty easy for someone to calculate who deposited how much.

We thought about a centralized option where we only hold the viewing keys and show a delayed balance, but this would mean that the user base would have to take our word for it.

The point of blockchain is to be decentralized and trustless. One scam I can think of off the top of my head would be to inflate our numbers so as to attract more investors.

We think privacy is important, but it should be privacy for individuals and transparency for organizations.
