# Profit distributor
btn.group's profit distributor.

## How it works
* User deposits Buttcoin into this smart contract.
* This smart contract receives profits and distributes to users.

## The three pillars of blockchain
The three pillars refers to blockchain itself but we are attempting to follow the ethos as much as possible.

### 1. Decentralization
This contract has a few admin functions
1. Change admin.
2. Register receivable profit token - Had to make registering of receivable profit tokens admin only, as someone could add a tonne of random tokens which would make the contract unusable due to fees.
3. Initialize the pool shares token - This is done via the smart contract so that the smart contract, not and user, to allow this smart contract to mint the shares token when a user depots Buttcoin.
4. Set the pool shares token details into configuration. This can only be done one time so as to prevent any hack.

### 2. Transparency
All involved smart contracts are publicly viewable and audited by third parties. 
1. Buttcoin balance of contract is publicly viewable.
2. The total raised for each profit cryptocurrency is publicly viewable.
3. The balance for each profit token is publicly viewable.
4. The balance for pool shares token is publicly viewable.

### 3. Immutability
This is secured by the Secret network.

## Regarding privacy
We have thought long and hard about this and have decided to make many aspects public. This means that it would be pretty easy for someone to calculate who deposited how much.

We thought about a centralized option where we only hold the viewing keys and show a delayed balance, but this would mean that the user base would have to take our word for it.

The point of blockchain is to be decentralized and trustless. One scam I can think of off the top of my head would be to inflate our numbers so as to attract more investors.

We think privacy is important, but it should be privacy for individuals and transparency for organizations.

###  Why we implemented then removed the pool shares token
The only reason we implemented a pool shares token was so that it could be used for users that deposited Buttcoin into this contract to still be able to vote. With what's going on in the world and from what I've seen in other crypto protocols, governance is a total sham. It's being used to look like there is a democratic proccess to disguise clear and present nepotism. Blockchain was created to counter this sort of thing. "Code is law" is the ethos. If there was ever to be a democrating process, it must be based on one vote per person. I understand that democracy amongst share holders is different, but I don't like how this false democracy is being portrayed to users. We are going to stick to immutable code as was intended.
