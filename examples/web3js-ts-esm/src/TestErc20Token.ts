export const TestErc20Token = {
    "contractName": "TestErc20Token",
    "abi": [
      {
        "constant": true,
        "inputs": [],
        "name": "name",
        "outputs": [
          {
            "name": "",
            "type": "string"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "spender",
            "type": "address"
          },
          {
            "name": "value",
            "type": "uint256"
          }
        ],
        "name": "approve",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": true,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [
          {
            "name": "",
            "type": "uint256"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "sender",
            "type": "address"
          },
          {
            "name": "recipient",
            "type": "address"
          },
          {
            "name": "amount",
            "type": "uint256"
          }
        ],
        "name": "transferFrom",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": true,
        "inputs": [],
        "name": "decimals",
        "outputs": [
          {
            "name": "",
            "type": "uint8"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "spender",
            "type": "address"
          },
          {
            "name": "addedValue",
            "type": "uint256"
          }
        ],
        "name": "increaseAllowance",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "account",
            "type": "address"
          },
          {
            "name": "amount",
            "type": "uint256"
          }
        ],
        "name": "mint",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": true,
        "inputs": [
          {
            "name": "account",
            "type": "address"
          }
        ],
        "name": "balanceOf",
        "outputs": [
          {
            "name": "",
            "type": "uint256"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": true,
        "inputs": [],
        "name": "symbol",
        "outputs": [
          {
            "name": "",
            "type": "string"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "account",
            "type": "address"
          }
        ],
        "name": "addMinter",
        "outputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [],
        "name": "renounceMinter",
        "outputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "spender",
            "type": "address"
          },
          {
            "name": "subtractedValue",
            "type": "uint256"
          }
        ],
        "name": "decreaseAllowance",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "recipient",
            "type": "address"
          },
          {
            "name": "amount",
            "type": "uint256"
          }
        ],
        "name": "transfer",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "constant": true,
        "inputs": [
          {
            "name": "account",
            "type": "address"
          }
        ],
        "name": "isMinter",
        "outputs": [
          {
            "name": "",
            "type": "bool"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": true,
        "inputs": [
          {
            "name": "owner",
            "type": "address"
          },
          {
            "name": "spender",
            "type": "address"
          }
        ],
        "name": "allowance",
        "outputs": [
          {
            "name": "",
            "type": "uint256"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "inputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "constructor"
      },
      {
        "anonymous": false,
        "inputs": [
          {
            "indexed": true,
            "name": "account",
            "type": "address"
          }
        ],
        "name": "MinterAdded",
        "type": "event"
      },
      {
        "anonymous": false,
        "inputs": [
          {
            "indexed": true,
            "name": "account",
            "type": "address"
          }
        ],
        "name": "MinterRemoved",
        "type": "event"
      },
      {
        "anonymous": false,
        "inputs": [
          {
            "indexed": true,
            "name": "from",
            "type": "address"
          },
          {
            "indexed": true,
            "name": "to",
            "type": "address"
          },
          {
            "indexed": false,
            "name": "value",
            "type": "uint256"
          }
        ],
        "name": "Transfer",
        "type": "event"
      },
      {
        "anonymous": false,
        "inputs": [
          {
            "indexed": true,
            "name": "owner",
            "type": "address"
          },
          {
            "indexed": true,
            "name": "spender",
            "type": "address"
          },
          {
            "indexed": false,
            "name": "value",
            "type": "uint256"
          }
        ],
        "name": "Approval",
        "type": "event"
      }
    ],
    "bytecode": "0x60806040523480156200001157600080fd5b506040518060400160405280600a81526020017f5465737420546f6b656e000000000000000000000000000000000000000000008152506040518060400160405280600281526020017f545400000000000000000000000000000000000000000000000000000000000081525060126200009133620000da60201b60201c565b8251620000a690600490602086019062000256565b508151620000bc90600590602085019062000256565b506006805460ff191660ff9290921691909117905550620002fb9050565b620000f58160036200012c60201b62000b5c1790919060201c565b6040516001600160a01b038216907f6ae172837ea30b801fbfcdd4108aa1d5bf8ff775444fd70256b44e6bf3dfc3f690600090a250565b6200014182826001600160e01b03620001d316565b15620001ae57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601f60248201527f526f6c65733a206163636f756e7420616c72656164792068617320726f6c6500604482015290519081900360640190fd5b6001600160a01b0316600090815260209190915260409020805460ff19166001179055565b60006001600160a01b03821662000236576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526022815260200180620010856022913960400191505060405180910390fd5b506001600160a01b03166000908152602091909152604090205460ff1690565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106200029957805160ff1916838001178555620002c9565b82800160010185558215620002c9579182015b82811115620002c9578251825591602001919060010190620002ac565b50620002d7929150620002db565b5090565b620002f891905b80821115620002d75760008155600101620002e2565b90565b610d7a806200030b6000396000f3fe608060405234801561001057600080fd5b50600436106100f55760003560e01c806370a0823111610097578063a457c2d711610066578063a457c2d7146102db578063a9059cbb14610307578063aa271e1a14610333578063dd62ed3e14610359576100f5565b806370a082311461027d57806395d89b41146102a3578063983b2d56146102ab57806398650275146102d3576100f5565b806323b872dd116100d357806323b872dd146101d1578063313ce56714610207578063395093511461022557806340c10f1914610251576100f5565b806306fdde03146100fa578063095ea7b31461017757806318160ddd146101b7575b600080fd5b610102610387565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561013c578181015183820152602001610124565b50505050905090810190601f1680156101695780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101a36004803603604081101561018d57600080fd5b506001600160a01b03813516906020013561041d565b604080519115158252519081900360200190f35b6101bf610433565b60408051918252519081900360200190f35b6101a3600480360360608110156101e757600080fd5b506001600160a01b03813581169160208101359091169060400135610439565b61020f610490565b6040805160ff9092168252519081900360200190f35b6101a36004803603604081101561023b57600080fd5b506001600160a01b038135169060200135610499565b6101a36004803603604081101561026757600080fd5b506001600160a01b0381351690602001356104d5565b6101bf6004803603602081101561029357600080fd5b50356001600160a01b0316610525565b610102610540565b6102d1600480360360208110156102c157600080fd5b50356001600160a01b03166105a1565b005b6102d16105f1565b6101a3600480360360408110156102f157600080fd5b506001600160a01b0381351690602001356105fc565b6101a36004803603604081101561031d57600080fd5b506001600160a01b038135169060200135610638565b6101a36004803603602081101561034957600080fd5b50356001600160a01b0316610645565b6101bf6004803603604081101561036f57600080fd5b506001600160a01b038135811691602001351661065e565b60048054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156104135780601f106103e857610100808354040283529160200191610413565b820191906000526020600020905b8154815290600101906020018083116103f657829003601f168201915b5050505050905090565b600061042a338484610689565b50600192915050565b60025490565b6000610446848484610775565b6001600160a01b038416600090815260016020908152604080832033808552925290912054610486918691610481908663ffffffff6108b716565b610689565b5060019392505050565b60065460ff1690565b3360008181526001602090815260408083206001600160a01b0387168452909152812054909161042a918590610481908663ffffffff61091416565b60006104e033610645565b61051b5760405162461bcd60e51b8152600401808060200182810382526030815260200180610c8a6030913960400191505060405180910390fd5b61042a8383610975565b6001600160a01b031660009081526020819052604090205490565b60058054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156104135780601f106103e857610100808354040283529160200191610413565b6105aa33610645565b6105e55760405162461bcd60e51b8152600401808060200182810382526030815260200180610c8a6030913960400191505060405180910390fd5b6105ee81610a65565b50565b6105fa33610aad565b565b3360008181526001602090815260408083206001600160a01b0387168452909152812054909161042a918590610481908663ffffffff6108b716565b600061042a338484610775565b600061065860038363ffffffff610af516565b92915050565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b6001600160a01b0383166106ce5760405162461bcd60e51b8152600401808060200182810382526024815260200180610d226024913960400191505060405180910390fd5b6001600160a01b0382166107135760405162461bcd60e51b8152600401808060200182810382526022815260200180610c686022913960400191505060405180910390fd5b6001600160a01b03808416600081815260016020908152604080832094871680845294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9259281900390910190a3505050565b6001600160a01b0383166107ba5760405162461bcd60e51b8152600401808060200182810382526025815260200180610cfd6025913960400191505060405180910390fd5b6001600160a01b0382166107ff5760405162461bcd60e51b8152600401808060200182810382526023815260200180610c456023913960400191505060405180910390fd5b6001600160a01b038316600090815260208190526040902054610828908263ffffffff6108b716565b6001600160a01b03808516600090815260208190526040808220939093559084168152205461085d908263ffffffff61091416565b6001600160a01b038084166000818152602081815260409182902094909455805185815290519193928716927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a3505050565b60008282111561090e576040805162461bcd60e51b815260206004820152601e60248201527f536166654d6174683a207375627472616374696f6e206f766572666c6f770000604482015290519081900360640190fd5b50900390565b60008282018381101561096e576040805162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b9392505050565b6001600160a01b0382166109d0576040805162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015290519081900360640190fd5b6002546109e3908263ffffffff61091416565b6002556001600160a01b038216600090815260208190526040902054610a0f908263ffffffff61091416565b6001600160a01b0383166000818152602081815260408083209490945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b610a7660038263ffffffff610b5c16565b6040516001600160a01b038216907f6ae172837ea30b801fbfcdd4108aa1d5bf8ff775444fd70256b44e6bf3dfc3f690600090a250565b610abe60038263ffffffff610bdd16565b6040516001600160a01b038216907fe94479a9f7e1952cc78f2d6baab678adc1b772d936c6583def489e524cb6669290600090a250565b60006001600160a01b038216610b3c5760405162461bcd60e51b8152600401808060200182810382526022815260200180610cdb6022913960400191505060405180910390fd5b506001600160a01b03166000908152602091909152604090205460ff1690565b610b668282610af5565b15610bb8576040805162461bcd60e51b815260206004820152601f60248201527f526f6c65733a206163636f756e7420616c72656164792068617320726f6c6500604482015290519081900360640190fd5b6001600160a01b0316600090815260209190915260409020805460ff19166001179055565b610be78282610af5565b610c225760405162461bcd60e51b8152600401808060200182810382526021815260200180610cba6021913960400191505060405180910390fd5b6001600160a01b0316600090815260209190915260409020805460ff1916905556fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f20616464726573734d696e746572526f6c653a2063616c6c657220646f6573206e6f74206861766520746865204d696e74657220726f6c65526f6c65733a206163636f756e7420646f6573206e6f74206861766520726f6c65526f6c65733a206163636f756e7420697320746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f2061646472657373a265627a7a72305820337bf5e979f127f42f6d97404492c0ad94b6efa80434ebee350caf56bb53f98f64736f6c63430005090032526f6c65733a206163636f756e7420697320746865207a65726f2061646472657373",
    "deployedBytecode": "0x608060405234801561001057600080fd5b50600436106100f55760003560e01c806370a0823111610097578063a457c2d711610066578063a457c2d7146102db578063a9059cbb14610307578063aa271e1a14610333578063dd62ed3e14610359576100f5565b806370a082311461027d57806395d89b41146102a3578063983b2d56146102ab57806398650275146102d3576100f5565b806323b872dd116100d357806323b872dd146101d1578063313ce56714610207578063395093511461022557806340c10f1914610251576100f5565b806306fdde03146100fa578063095ea7b31461017757806318160ddd146101b7575b600080fd5b610102610387565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561013c578181015183820152602001610124565b50505050905090810190601f1680156101695780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101a36004803603604081101561018d57600080fd5b506001600160a01b03813516906020013561041d565b604080519115158252519081900360200190f35b6101bf610433565b60408051918252519081900360200190f35b6101a3600480360360608110156101e757600080fd5b506001600160a01b03813581169160208101359091169060400135610439565b61020f610490565b6040805160ff9092168252519081900360200190f35b6101a36004803603604081101561023b57600080fd5b506001600160a01b038135169060200135610499565b6101a36004803603604081101561026757600080fd5b506001600160a01b0381351690602001356104d5565b6101bf6004803603602081101561029357600080fd5b50356001600160a01b0316610525565b610102610540565b6102d1600480360360208110156102c157600080fd5b50356001600160a01b03166105a1565b005b6102d16105f1565b6101a3600480360360408110156102f157600080fd5b506001600160a01b0381351690602001356105fc565b6101a36004803603604081101561031d57600080fd5b506001600160a01b038135169060200135610638565b6101a36004803603602081101561034957600080fd5b50356001600160a01b0316610645565b6101bf6004803603604081101561036f57600080fd5b506001600160a01b038135811691602001351661065e565b60048054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156104135780601f106103e857610100808354040283529160200191610413565b820191906000526020600020905b8154815290600101906020018083116103f657829003601f168201915b5050505050905090565b600061042a338484610689565b50600192915050565b60025490565b6000610446848484610775565b6001600160a01b038416600090815260016020908152604080832033808552925290912054610486918691610481908663ffffffff6108b716565b610689565b5060019392505050565b60065460ff1690565b3360008181526001602090815260408083206001600160a01b0387168452909152812054909161042a918590610481908663ffffffff61091416565b60006104e033610645565b61051b5760405162461bcd60e51b8152600401808060200182810382526030815260200180610c8a6030913960400191505060405180910390fd5b61042a8383610975565b6001600160a01b031660009081526020819052604090205490565b60058054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156104135780601f106103e857610100808354040283529160200191610413565b6105aa33610645565b6105e55760405162461bcd60e51b8152600401808060200182810382526030815260200180610c8a6030913960400191505060405180910390fd5b6105ee81610a65565b50565b6105fa33610aad565b565b3360008181526001602090815260408083206001600160a01b0387168452909152812054909161042a918590610481908663ffffffff6108b716565b600061042a338484610775565b600061065860038363ffffffff610af516565b92915050565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b6001600160a01b0383166106ce5760405162461bcd60e51b8152600401808060200182810382526024815260200180610d226024913960400191505060405180910390fd5b6001600160a01b0382166107135760405162461bcd60e51b8152600401808060200182810382526022815260200180610c686022913960400191505060405180910390fd5b6001600160a01b03808416600081815260016020908152604080832094871680845294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9259281900390910190a3505050565b6001600160a01b0383166107ba5760405162461bcd60e51b8152600401808060200182810382526025815260200180610cfd6025913960400191505060405180910390fd5b6001600160a01b0382166107ff5760405162461bcd60e51b8152600401808060200182810382526023815260200180610c456023913960400191505060405180910390fd5b6001600160a01b038316600090815260208190526040902054610828908263ffffffff6108b716565b6001600160a01b03808516600090815260208190526040808220939093559084168152205461085d908263ffffffff61091416565b6001600160a01b038084166000818152602081815260409182902094909455805185815290519193928716927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a3505050565b60008282111561090e576040805162461bcd60e51b815260206004820152601e60248201527f536166654d6174683a207375627472616374696f6e206f766572666c6f770000604482015290519081900360640190fd5b50900390565b60008282018381101561096e576040805162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b9392505050565b6001600160a01b0382166109d0576040805162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015290519081900360640190fd5b6002546109e3908263ffffffff61091416565b6002556001600160a01b038216600090815260208190526040902054610a0f908263ffffffff61091416565b6001600160a01b0383166000818152602081815260408083209490945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b610a7660038263ffffffff610b5c16565b6040516001600160a01b038216907f6ae172837ea30b801fbfcdd4108aa1d5bf8ff775444fd70256b44e6bf3dfc3f690600090a250565b610abe60038263ffffffff610bdd16565b6040516001600160a01b038216907fe94479a9f7e1952cc78f2d6baab678adc1b772d936c6583def489e524cb6669290600090a250565b60006001600160a01b038216610b3c5760405162461bcd60e51b8152600401808060200182810382526022815260200180610cdb6022913960400191505060405180910390fd5b506001600160a01b03166000908152602091909152604090205460ff1690565b610b668282610af5565b15610bb8576040805162461bcd60e51b815260206004820152601f60248201527f526f6c65733a206163636f756e7420616c72656164792068617320726f6c6500604482015290519081900360640190fd5b6001600160a01b0316600090815260209190915260409020805460ff19166001179055565b610be78282610af5565b610c225760405162461bcd60e51b8152600401808060200182810382526021815260200180610cba6021913960400191505060405180910390fd5b6001600160a01b0316600090815260209190915260409020805460ff1916905556fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f20616464726573734d696e746572526f6c653a2063616c6c657220646f6573206e6f74206861766520746865204d696e74657220726f6c65526f6c65733a206163636f756e7420646f6573206e6f74206861766520726f6c65526f6c65733a206163636f756e7420697320746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f2061646472657373a265627a7a72305820337bf5e979f127f42f6d97404492c0ad94b6efa80434ebee350caf56bb53f98f64736f6c63430005090032",
    "networks": {},
    "schemaVersion": "3.0.11",
    "updatedAt": "2019-06-21T16:10:58.686Z",
    "devdoc": {
      "methods": {
        "allowance(address,address)": {
          "details": "See `IERC20.allowance`."
        },
        "approve(address,uint256)": {
          "details": "See `IERC20.approve`.     * Requirements:     * - `spender` cannot be the zero address."
        },
        "balanceOf(address)": {
          "details": "See `IERC20.balanceOf`."
        },
        "decimals()": {
          "details": "Returns the number of decimals used to get its user representation. For example, if `decimals` equals `2`, a balance of `505` tokens should be displayed to a user as `5,05` (`505 / 10 ** 2`).     * Tokens usually opt for a value of 18, imitating the relationship between Ether and Wei.     * > Note that this information is only used for _display_ purposes: it in no way affects any of the arithmetic of the contract, including `IERC20.balanceOf` and `IERC20.transfer`."
        },
        "decreaseAllowance(address,uint256)": {
          "details": "Atomically decreases the allowance granted to `spender` by the caller.     * This is an alternative to `approve` that can be used as a mitigation for problems described in `IERC20.approve`.     * Emits an `Approval` event indicating the updated allowance.     * Requirements:     * - `spender` cannot be the zero address. - `spender` must have allowance for the caller of at least `subtractedValue`."
        },
        "increaseAllowance(address,uint256)": {
          "details": "Atomically increases the allowance granted to `spender` by the caller.     * This is an alternative to `approve` that can be used as a mitigation for problems described in `IERC20.approve`.     * Emits an `Approval` event indicating the updated allowance.     * Requirements:     * - `spender` cannot be the zero address."
        },
        "mint(address,uint256)": {
          "details": "See `ERC20._mint`.     * Requirements:     * - the caller must have the `MinterRole`."
        },
        "name()": {
          "details": "Returns the name of the token."
        },
        "symbol()": {
          "details": "Returns the symbol of the token, usually a shorter version of the name."
        },
        "totalSupply()": {
          "details": "See `IERC20.totalSupply`."
        },
        "transfer(address,uint256)": {
          "details": "See `IERC20.transfer`.     * Requirements:     * - `recipient` cannot be the zero address. - the caller must have a balance of at least `amount`."
        },
        "transferFrom(address,address,uint256)": {
          "details": "See `IERC20.transferFrom`.     * Emits an `Approval` event indicating the updated allowance. This is not required by the EIP. See the note at the beginning of `ERC20`;     * Requirements: - `sender` and `recipient` cannot be the zero address. - `sender` must have a balance of at least `value`. - the caller must have allowance for `sender`'s tokens of at least `amount`."
        }
      }
    },
    "userdoc": {
      "methods": {},
      "notice": "This is an implementation of an ERC20 token to be used in tests. It's a standard ERC20 implementation + `mint` (for testing). * This contract should not be used in production."
    }
  } as const;