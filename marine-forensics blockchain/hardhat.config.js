require("@nomiclabs/hardhat-ethers");

// Load environment variables (optional, for security)
// require("dotenv").config();

const INFURA_API_KEY = "592071cb68f14c67bc929dfc2e76af78";
const DEPLOYER_PRIVATE_KEY = process.env.PRIVATE_KEY || "0x2709827e6922ab3c9cd68617ae6feb1cae4000b47a7a33cbd0bc50d212aa2685";

module.exports = {
  solidity: "0.8.0",
  networks: {
    // Local Hardhat node (for development/testing)
    hardhat: {
      chainId: 1337
    },
    // Ethereum Sepolia Testnet (for public deployment)
    sepolia: {
      url: `https://sepolia.infura.io/v3/${INFURA_API_KEY}`,
      accounts: DEPLOYER_PRIVATE_KEY !== "YOUR_WALLET_PRIVATE_KEY_HERE"
        ? [DEPLOYER_PRIVATE_KEY]
        : [],
      chainId: 11155111
    },
    // Ethereum Mainnet (for production — use with caution!)
    mainnet: {
      url: `https://mainnet.infura.io/v3/${INFURA_API_KEY}`,
      accounts: DEPLOYER_PRIVATE_KEY !== "YOUR_WALLET_PRIVATE_KEY_HERE"
        ? [DEPLOYER_PRIVATE_KEY]
        : [],
      chainId: 1
    }
  }
};

