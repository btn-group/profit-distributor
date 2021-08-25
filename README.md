# Profit distributor
btn.group's profit distributor.

## How it works
* User deposits Buttcoin into this smart contract.
* This smart contract receives profits and distributes to users.

## The three pillars of blockchain
The three pillars refers to blockchain itself but we are attempting to follow the ethos as much as possible.

### 1. Decentralization
This contract has no admin functions once initialized

### 2. Transparency
All involved smart contracts are publicly viewable and audited by third parties. All aspects of this smart contract is public.

### 3. Immutability
This is secured by the Secret network.

## Regarding privacy
We have thought long and hard about this and have decided to make all aspects public. 

We thought about a centralized option where we only hold the viewing keys and show a delayed balance, but this would mean that the user base would have to take our word for it.

The point of blockchain is to be decentralized and trustless. One scam I can think of off the top of my head would be to inflate our numbers so as to attract more investors.

We think privacy is important, but it should be privacy for individuals and transparency for organizations.

###  Why we implemented then removed the pool shares token
The only reason we implemented a pool shares token was so that it could be used for users that deposited Buttcoin into this contract to still be able to vote. With what's going on in the world and from what I've seen in other crypto protocols, governance is a total sham. It's being used to look like there is a democratic process to disguise clear and present nepotism. Blockchain was created to counter this sort of thing. "Code is law" is the ethos. If there was ever to be a democratizing process, it must be based on one vote per person. I understand that democracy amongst share holders is different, but I don't like how this false democracy is being portrayed to users. We are going to stick to immutable code as was intended when Blockchain was conceptualized.

## Testing locally
```
// 1. Run chain locally
docker run -it --rm -p 26657:26657 -p 26656:26656 -p 1337:1337 -v $(pwd):/root/code --name secretdev enigmampc/secret-network-sw-dev

// 2. Access container via separate terminal window
docker exec -it secretdev /bin/bash

// 3. cd into code folder
cd code

// 4. Store the contract (Specify your keyring. Mine is named test etc.)
secretcli tx compute store buttcoin-distributor.wasm.gz --from a --gas 3000000 -y --keyring-backend test

// 5. Get the contract's id
secretcli query compute list-code

// 6. Init profit distributor 
CODE_ID=3
INIT='{"buttcoin": {"address": "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg", "contract_hash": "4CD7F64B9ADE65200E595216265932A0C7689C4804BE7B4A5F8CEBED250BF7EA"}, "profit_token": {"address": "secret13nkgqrfymug724h8pprpexqj9h629sa3heqh0t", "contract_hash": "35F5DB2BC5CD56815D10C7A567D6827BECCB8EAF45BC3FA016930C4A8209EA69"}, "viewing_key": "testing"}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "profit-distributor" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt
```
