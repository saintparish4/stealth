'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import { Upload, Play, Loader2, AlertTriangle, Zap, ChevronRight } from 'lucide-react'
import { Button } from '../../ui/button'
import { Card, CardContent } from '../../ui/card'

const CodeEditor = dynamic(
  () => import('./CodeEditor'),
  { 
    ssr: false,
    loading: () => (
      <div className="rounded-lg overflow-hidden border border-border/50 bg-card/50">
        <div className="flex items-center justify-center h-[630px]">
          <div className="text-muted-foreground font-mono text-sm font-light">
            Loading editor...
          </div>
        </div>
      </div>
    )
  }
)

// Example contracts for demonstration
const EXAMPLE_CONTRACTS = [
  {
    name: 'AaveOracle.sol',
    description: 'Aave oracle price feed',
    code: `// SPDX-License-Identifier: UNLICENSED
// Copyright (c) 2025 Aave Labs
pragma solidity 0.8.28;

import {AggregatorV3Interface} from 'src/dependencies/chainlink/AggregatorV3Interface.sol';
import {IAaveOracle, IPriceOracle} from 'src/spoke/interfaces/IAaveOracle.sol';

/// @title AaveOracle
/// @author Aave Labs
/// @notice Provides reserve prices.
/// @dev Oracles are spoke-specific, due to the usage of reserve id as index of the \`_sources\` mapping.
contract AaveOracle is IAaveOracle {
  /// @inheritdoc IPriceOracle
  address public immutable SPOKE;

  /// @inheritdoc IPriceOracle
  uint8 public immutable DECIMALS;

  /// @inheritdoc IAaveOracle
  string public DESCRIPTION;

  mapping(uint256 reserveId => AggregatorV3Interface) internal _sources;

  /// @dev Constructor.
  /// @dev \`decimals\` must match the spoke's decimals for compatibility.
  /// @param spoke_ The address of the spoke contract.
  /// @param decimals_ The number of decimals for the oracle.
  /// @param description_ The description of the oracle.
  constructor(address spoke_, uint8 decimals_, string memory description_) {
    require(spoke_ != address(0), InvalidAddress());
    SPOKE = spoke_;
    DECIMALS = decimals_;
    DESCRIPTION = description_;
  }

  /// @inheritdoc IAaveOracle
  function setReserveSource(uint256 reserveId, address source) external {
    require(msg.sender == SPOKE, OnlySpoke());
    AggregatorV3Interface targetSource = AggregatorV3Interface(source);
    require(targetSource.decimals() == DECIMALS, InvalidSourceDecimals(reserveId));
    _sources[reserveId] = targetSource;
    _getSourcePrice(reserveId);
    emit UpdateReserveSource(reserveId, source);
  }

  /// @inheritdoc IPriceOracle
  function getReservePrice(uint256 reserveId) external view returns (uint256) {
    return _getSourcePrice(reserveId);
  }

  /// @inheritdoc IAaveOracle
  function getReservesPrices(
    uint256[] calldata reserveIds
  ) external view returns (uint256[] memory) {
    uint256[] memory prices = new uint256[](reserveIds.length);
    for (uint256 i = 0; i < reserveIds.length; ++i) {
      prices[i] = _getSourcePrice(reserveIds[i]);
    }
    return prices;
  }

  /// @inheritdoc IAaveOracle
  function getReserveSource(uint256 reserveId) external view returns (address) {
    return address(_sources[reserveId]);
  }

  /// @dev Price of zero will revert with \`InvalidPrice\`.
  function _getSourcePrice(uint256 reserveId) internal view returns (uint256) {
    AggregatorV3Interface source = _sources[reserveId];
    require(address(source) != address(0), InvalidSource(reserveId));

    (, int256 price, , , ) = source.latestRoundData();
    require(price > 0, InvalidPrice(reserveId));

    return uint256(price);
  }
}`
  },
  {
    name: 'AssetInterestRateStrategy.sol',
    description: 'Aave kink-based interest rates',
    code: `// SPDX-License-Identifier: UNLICENSED
// Copyright (c) 2025 Aave Labs
pragma solidity 0.8.28;

import {WadRayMath} from 'src/libraries/math/WadRayMath.sol';
import {IAssetInterestRateStrategy, IBasicInterestRateStrategy} from 'src/hub/interfaces/IAssetInterestRateStrategy.sol';

/// @title AssetInterestRateStrategy
/// @author Aave Labs
/// @notice Manages the kink-based interest rate strategy for an asset.
/// @dev Strategies are Hub-specific, due to the usage of asset identifier as index of the \`_interestRateData\` mapping.
contract AssetInterestRateStrategy is IAssetInterestRateStrategy {
  using WadRayMath for *;

  /// @inheritdoc IAssetInterestRateStrategy
  uint256 public constant MAX_BORROW_RATE = 1000_00;

  /// @inheritdoc IAssetInterestRateStrategy
  uint256 public constant MIN_OPTIMAL_RATIO = 1_00;

  /// @inheritdoc IAssetInterestRateStrategy
  uint256 public constant MAX_OPTIMAL_RATIO = 99_00;

  /// @inheritdoc IAssetInterestRateStrategy
  address public immutable HUB;

  /// @dev Map of asset identifiers to their interest rate data.
  mapping(uint256 assetId => InterestRateData) internal _interestRateData;

  /// @dev Constructor.
  /// @param hub_ The address of the associated Hub.
  constructor(address hub_) {
    require(hub_ != address(0), InvalidAddress());
    HUB = hub_;
  }

  /// @notice Sets the interest rate parameters for a specified asset.
  /// @param assetId The identifier of the asset.
  /// @param data The encoded parameters containing BPS data used to configure the interest rate of the asset.
  function setInterestRateData(uint256 assetId, bytes calldata data) external {
    require(HUB == msg.sender, OnlyHub());
    InterestRateData memory rateData = abi.decode(data, (InterestRateData));
    require(
      MIN_OPTIMAL_RATIO <= rateData.optimalUsageRatio &&
        rateData.optimalUsageRatio <= MAX_OPTIMAL_RATIO,
      InvalidOptimalUsageRatio()
    );
    require(rateData.variableRateSlope1 <= rateData.variableRateSlope2, Slope2MustBeGteSlope1());
    require(
      rateData.baseVariableBorrowRate + rateData.variableRateSlope1 + rateData.variableRateSlope2 <=
        MAX_BORROW_RATE,
      InvalidMaxRate()
    );

    _interestRateData[assetId] = rateData;

    emit UpdateRateData(
      HUB,
      assetId,
      rateData.optimalUsageRatio,
      rateData.baseVariableBorrowRate,
      rateData.variableRateSlope1,
      rateData.variableRateSlope2
    );
  }

  /// @inheritdoc IAssetInterestRateStrategy
  function getInterestRateData(uint256 assetId) external view returns (InterestRateData memory) {
    return _interestRateData[assetId];
  }

  /// @inheritdoc IAssetInterestRateStrategy
  function getOptimalUsageRatio(uint256 assetId) external view returns (uint256) {
    return _interestRateData[assetId].optimalUsageRatio;
  }

  /// @inheritdoc IAssetInterestRateStrategy
  function getBaseVariableBorrowRate(uint256 assetId) external view returns (uint256) {
    return _interestRateData[assetId].baseVariableBorrowRate;
  }

  /// @inheritdoc IAssetInterestRateStrategy
  function getVariableRateSlope1(uint256 assetId) external view returns (uint256) {
    return _interestRateData[assetId].variableRateSlope1;
  }

  /// @inheritdoc IAssetInterestRateStrategy
  function getVariableRateSlope2(uint256 assetId) external view returns (uint256) {
    return _interestRateData[assetId].variableRateSlope2;
  }

  /// @inheritdoc IAssetInterestRateStrategy
  function getMaxVariableBorrowRate(uint256 assetId) external view returns (uint256) {
    return
      _interestRateData[assetId].baseVariableBorrowRate +
      _interestRateData[assetId].variableRateSlope1 +
      _interestRateData[assetId].variableRateSlope2;
  }

  /// @inheritdoc IBasicInterestRateStrategy
  function calculateInterestRate(
    uint256 assetId,
    uint256 liquidity,
    uint256 drawn,
    uint256 /* deficit */,
    uint256 swept
  ) external view returns (uint256) {
    InterestRateData memory rateData = _interestRateData[assetId];
    require(rateData.optimalUsageRatio > 0, InterestRateDataNotSet(assetId));

    uint256 currentVariableBorrowRateRay = rateData.baseVariableBorrowRate.bpsToRay();
    if (drawn == 0) {
      return currentVariableBorrowRateRay;
    }

    uint256 usageRatioRay = drawn.rayDivUp(liquidity + drawn + swept);
    uint256 optimalUsageRatioRay = rateData.optimalUsageRatio.bpsToRay();

    if (usageRatioRay <= optimalUsageRatioRay) {
      currentVariableBorrowRateRay += rateData
        .variableRateSlope1
        .bpsToRay()
        .rayMulUp(usageRatioRay)
        .rayDivUp(optimalUsageRatioRay);
    } else {
      currentVariableBorrowRateRay +=
        rateData.variableRateSlope1.bpsToRay() +
        rateData
          .variableRateSlope2
          .bpsToRay()
          .rayMulUp(usageRatioRay - optimalUsageRatioRay)
          .rayDivUp(WadRayMath.RAY - optimalUsageRatioRay);
    }

    return currentVariableBorrowRateRay;
  }
}`
  },
  {
    name: 'CrosschainLinked.sol',
    description: 'ERC-7786 cross-chain bridging',
    code: `// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {IERC7786GatewaySource} from "../interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "../utils/draft-InteroperableAddress.sol";
import {Bytes} from "../utils/Bytes.sol";
import {ERC7786Recipient} from "./ERC7786Recipient.sol";

/**
 * @dev Core bridging mechanism.
 *
 * This contract contains the logic to register and send messages to counterparts on remote chains using ERC-7786
 * gateways. It ensure received messages originate from a counterpart. This is the base of token bridges such as
 * {BridgeERC20Core}.
 *
 * Contracts that inherit from this contract can use the internal {_sendMessageToCounterpart} to send messages to their
 * counterpart on a foreign chain. They must override the {_processMessage} function to handle messages that have
 * been verified.
 */
abstract contract CrosschainLinked is ERC7786Recipient {
    using Bytes for bytes;
    using InteroperableAddress for bytes;

    struct Link {
        address gateway;
        bytes counterpart; // Full InteroperableAddress (chain ref + address)
    }
    mapping(bytes chain => Link) private _links;

    /**
     * @dev Emitted when a new link is registered.
     *
     * Note: the \`counterpart\` argument is a full InteroperableAddress (chain ref + address).
     */
    event LinkRegistered(address gateway, bytes counterpart);

    /**
     * @dev Reverted when trying to register a link for a chain that is already registered.
     *
     * Note: the \`chain\` argument is a "chain-only" InteroperableAddress (empty address).
     */
    error LinkAlreadyRegistered(bytes chain);

    constructor(Link[] memory links) {
        for (uint256 i = 0; i < links.length; ++i) {
            _setLink(links[i].gateway, links[i].counterpart, false);
        }
    }

    /**
     * @dev Returns the ERC-7786 gateway used for sending and receiving cross-chain messages to a given chain.
     *
     * Note: The \`chain\` parameter is a "chain-only" InteroperableAddress (empty address) and the \`counterpart\` returns
     * the full InteroperableAddress (chain ref + address) that is on \`chain\`.
     */
    function getLink(bytes memory chain) public view virtual returns (address gateway, bytes memory counterpart) {
        Link storage self = _links[chain];
        return (self.gateway, self.counterpart);
    }

    /**
     * @dev Internal setter to change the ERC-7786 gateway and counterpart for a given chain. Called at construction.
     *
     * Note: The \`counterpart\` parameter is the full InteroperableAddress (chain ref + address).
     */
    function _setLink(address gateway, bytes memory counterpart, bool allowOverride) internal virtual {
        // Sanity check, this should revert if gateway is not an ERC-7786 implementation. Note that since
        // supportsAttribute returns data, an EOA would fail that test (nothing returned).
        IERC7786GatewaySource(gateway).supportsAttribute(bytes4(0));

        bytes memory chain = _extractChain(counterpart);
        if (allowOverride || _links[chain].gateway == address(0)) {
            _links[chain] = Link(gateway, counterpart);
            emit LinkRegistered(gateway, counterpart);
        } else {
            revert LinkAlreadyRegistered(chain);
        }
    }

    /**
     * @dev Internal messaging function
     *
     * Note: The \`chain\` parameter is a "chain-only" InteroperableAddress (empty address).
     */
    function _sendMessageToCounterpart(
        bytes memory chain,
        bytes memory payload,
        bytes[] memory attributes
    ) internal virtual returns (bytes32) {
        (address gateway, bytes memory counterpart) = getLink(chain);
        return IERC7786GatewaySource(gateway).sendMessage(counterpart, payload, attributes);
    }

    /// @inheritdoc ERC7786Recipient
    function _isAuthorizedGateway(
        address instance,
        bytes calldata sender
    ) internal view virtual override returns (bool) {
        (address gateway, bytes memory router) = getLink(_extractChain(sender));
        return instance == gateway && sender.equal(router);
    }

    function _extractChain(bytes memory self) private pure returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference, ) = self.parseV1();
        return InteroperableAddress.formatV1(chainType, chainReference, hex"");
    }
}`
  },
  {
    name: 'ClaimsRegistry.sol',
    description: 'Healthcare claims management',
    code: `// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";

/**
 * @title ClaimsRegistry
 * @notice Manages healthcare claim submission, verification, and lifecycle
 * @dev Stores claim hashes on-chain, full data stored off-chain (IPFS)
 */
contract ClaimsRegistry is AccessControl, ReentrancyGuard, Pausable {
    // ============ Constants ============
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    uint256 public constant VERIFICATION_THRESHOLD = 2; // Minimum verifiers needed
    uint256 public constant VERIFICATION_WINDOW = 7 days;
    uint256 public constant MAX_CLAIM_AMOUNT = 1_000_000 * 1e18; // $1M max claim

    // ============ Types ============
    enum ClaimStatus {
        None,
        Submitted,
        UnderReview,
        Approved,
        Rejected,
        Disputed,
        Expired
    }

    struct Claim {
        bytes32 claimId;
        address provider;
        bytes32 dataHash; // Keccak256 of claim data
        string ipfsCid; // IPFS Content ID for full data
        uint256 amount; // Claim amount in wei (or smallest unit)
        uint256 submittedAt;
        uint256 verifiedAt;
        ClaimStatus status;
        uint256 approvalsCount;
        uint256 rejectionsCount;
        string rejectionReason;
    }

    struct Verification {
        address verifier;
        bool approved;
        string reason;
        uint256 timestamp;
    }

    // ============ State ============
    ProviderRegistry public providerRegistry;

    mapping(bytes32 => Claim) public claims;
    mapping(bytes32 => mapping(address => Verification)) public verifications;
    mapping(bytes32 => address[]) public claimVerifiers;
    mapping(address => bytes32[]) public providerClaims;

    bytes32[] public allClaimIds;
    uint256 public totalClaims;
    uint256 public approvedClaims;
    uint256 public rejectedClaims;
    uint256 public totalAmountApproved;

    // ============ Events ============
    event ClaimSubmitted(
        bytes32 indexed claimId,
        address indexed provider,
        bytes32 dataHash,
        string ipfsCid,
        uint256 amount,
        uint256 timestamp
    );

    event ClaimVerificationSubmitted(
        bytes32 indexed claimId,
        address indexed verifier,
        bool approved,
        string reason,
        uint256 timestamp
    );

    event ClaimStatusChanged(
        bytes32 indexed claimId, ClaimStatus oldStatus, ClaimStatus newStatus, uint256 timestamp
    );

    event ClaimDisputed(
        bytes32 indexed claimId, address indexed disputedBy, string reason, uint256 timestamp
    );

    event ClaimExpired(bytes32 indexed claimId, uint256 timestamp);

    // ============ Errors ============
    error ProviderNotActive(address provider);
    error ClaimNotFound(bytes32 claimId);
    error ClaimAlreadyExists(bytes32 claimId);
    error InvalidClaimStatus(ClaimStatus current, ClaimStatus required);
    error AlreadyVerified(bytes32 claimId, address verifier);
    error InvalidClaimAmount(uint256 amount);
    error EmptyIPFSCid();
    error VerificationWindowExpired(bytes32 claimId);
    error InsufficientVerifications(uint256 current, uint256 required);

    // ============ Constructor ============
    constructor(address _providerRegistry) {
        providerRegistry = ProviderRegistry(_providerRegistry);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    // ============ External Functions ============

    /**
     * @notice Submit a new healthcare claim
     * @param dataHash Keccak256 hash of the claim data
     * @param ipfsCid IPFS Content ID where full claim data is stored
     * @param amount Claim amount
     * @return claimId The unique identifier for this claim
     */
    function submitClaim(bytes32 dataHash, string calldata ipfsCid, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 claimId)
    {
        // Verify provider is active
        if (!providerRegistry.isActiveProvider(msg.sender)) {
            revert ProviderNotActive(msg.sender);
        }

        // Validate inputs
        if (bytes(ipfsCid).length == 0) revert EmptyIPFSCid();
        if (amount == 0 || amount > MAX_CLAIM_AMOUNT) {
            revert InvalidClaimAmount(amount);
        }

        // Generate unique claim ID
        claimId = keccak256(abi.encodePacked(msg.sender, dataHash, block.timestamp, block.number));

        if (claims[claimId].status != ClaimStatus.None) {
            revert ClaimAlreadyExists(claimId);
        }

        // Store claim
        claims[claimId] = Claim({
            claimId: claimId,
            provider: msg.sender,
            dataHash: dataHash,
            ipfsCid: ipfsCid,
            amount: amount,
            submittedAt: block.timestamp,
            verifiedAt: 0,
            status: ClaimStatus.Submitted,
            approvalsCount: 0,
            rejectionsCount: 0,
            rejectionReason: ""
        });

        providerClaims[msg.sender].push(claimId);
        allClaimIds.push(claimId);
        totalClaims++;

        emit ClaimSubmitted(claimId, msg.sender, dataHash, ipfsCid, amount, block.timestamp);

        return claimId;
    }

    /**
     * @notice Submit verification for a claim (verifier only)
     * @param claimId The claim to verify
     * @param approved Whether to approve or reject
     * @param reason Reason for the decision
     */
    function submitVerification(bytes32 claimId, bool approved, string calldata reason)
        external
        onlyRole(VERIFIER_ROLE)
        nonReentrant
        whenNotPaused
    {
        Claim storage claim = claims[claimId];

        // Validate claim state
        if (claim.status == ClaimStatus.None) revert ClaimNotFound(claimId);
        if (claim.status != ClaimStatus.Submitted && claim.status != ClaimStatus.UnderReview) {
            revert InvalidClaimStatus(claim.status, ClaimStatus.Submitted);
        }

        // Check verification window
        if (block.timestamp > claim.submittedAt + VERIFICATION_WINDOW) {
            revert VerificationWindowExpired(claimId);
        }

        // Check if already verified by this verifier
        if (verifications[claimId][msg.sender].timestamp != 0) {
            revert AlreadyVerified(claimId, msg.sender);
        }

        // Store verification
        verifications[claimId][msg.sender] = Verification({
            verifier: msg.sender, approved: approved, reason: reason, timestamp: block.timestamp
        });
        claimVerifiers[claimId].push(msg.sender);

        // Update counts
        if (approved) {
            claim.approvalsCount++;
        } else {
            claim.rejectionsCount++;
            if (bytes(claim.rejectionReason).length == 0) {
                claim.rejectionReason = reason;
            }
        }

        // Update status to UnderReview if first verification
        if (claim.status == ClaimStatus.Submitted) {
            _updateStatus(claimId, ClaimStatus.UnderReview);
        }

        emit ClaimVerificationSubmitted(claimId, msg.sender, approved, reason, block.timestamp);

        // Check if we have enough verifications to finalize
        _checkAndFinalize(claimId);
    }

    /**
     * @notice Dispute an approved or rejected claim
     * @param claimId The claim to dispute
     * @param reason Reason for dispute
     */
    function disputeClaim(bytes32 claimId, string calldata reason) external whenNotPaused {
        Claim storage claim = claims[claimId];

        if (claim.status == ClaimStatus.None) revert ClaimNotFound(claimId);

        // Only provider or admin can dispute
        require(
            claim.provider == msg.sender || hasRole(ADMIN_ROLE, msg.sender),
            "Not authorized to dispute"
        );

        // Can only dispute approved or rejected claims
        require(
            claim.status == ClaimStatus.Approved || claim.status == ClaimStatus.Rejected,
            "Cannot dispute this claim"
        );

        _updateStatus(claimId, ClaimStatus.Disputed);

        emit ClaimDisputed(claimId, msg.sender, reason, block.timestamp);
    }

    /**
     * @notice Mark expired claims (can be called by anyone)
     * @param claimId The claim to check for expiration
     */
    function expireClaim(bytes32 claimId) external {
        Claim storage claim = claims[claimId];

        if (claim.status == ClaimStatus.None) revert ClaimNotFound(claimId);

        // Can only expire Submitted or UnderReview claims past the window
        require(
            claim.status == ClaimStatus.Submitted || claim.status == ClaimStatus.UnderReview,
            "Cannot expire this claim"
        );

        require(
            block.timestamp > claim.submittedAt + VERIFICATION_WINDOW,
            "Verification window still open"
        );

        _updateStatus(claimId, ClaimStatus.Expired);

        emit ClaimExpired(claimId, block.timestamp);
    }

    /**
     * @notice Force finalize a claim (admin only, for edge cases)
     * @param claimId The claim to finalize
     * @param approved Whether to approve
     * @param reason Reason for decision
     */
    function adminFinalize(bytes32 claimId, bool approved, string calldata reason)
        external
        onlyRole(ADMIN_ROLE)
    {
        Claim storage claim = claims[claimId];

        if (claim.status == ClaimStatus.None) revert ClaimNotFound(claimId);

        ClaimStatus newStatus = approved ? ClaimStatus.Approved : ClaimStatus.Rejected;
        _updateStatus(claimId, newStatus);

        if (!approved) {
            claim.rejectionReason = reason;
        }

        claim.verifiedAt = block.timestamp;

        // Update provider stats
        providerRegistry.recordClaimResult(claim.provider, approved);

        // Update totals
        if (approved) {
            approvedClaims++;
            totalAmountApproved += claim.amount;
        } else {
            rejectedClaims++;
        }
    }

    // ============ View Functions ============

    /**
     * @notice Get claim details
     */
    function getClaim(bytes32 claimId) external view returns (Claim memory) {
        return claims[claimId];
    }

    /**
     * @notice Get all verifications for a claim
     */
    function getClaimVerifications(bytes32 claimId) external view returns (Verification[] memory) {
        address[] memory verifierAddrs = claimVerifiers[claimId];
        Verification[] memory result = new Verification[](verifierAddrs.length);

        for (uint256 i = 0; i < verifierAddrs.length; i++) {
            result[i] = verifications[claimId][verifierAddrs[i]];
        }

        return result;
    }

    /**
     * @notice Get claims by provider (paginated)
     */
    function getProviderClaims(address provider, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory)
    {
        bytes32[] storage pClaims = providerClaims[provider];
        uint256 end = offset + limit;
        if (end > pClaims.length) {
            end = pClaims.length;
        }

        uint256 length = end > offset ? end - offset : 0;
        bytes32[] memory result = new bytes32[](length);

        for (uint256 i = 0; i < length; i++) {
            result[i] = pClaims[offset + i];
        }

        return result;
    }

    /**
     * @notice Get claims by status (paginated)
     * @dev This is expensive - for production, use off-chain indexing
     */
    function getClaimsByStatus(ClaimStatus status, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory)
    {
        // First pass: count matching claims
        uint256 count = 0;
        for (uint256 i = 0; i < allClaimIds.length; i++) {
            if (claims[allClaimIds[i]].status == status) {
                count++;
            }
        }

        // Second pass: collect with pagination
        bytes32[] memory result = new bytes32[](limit);
        uint256 found = 0;
        uint256 added = 0;

        for (uint256 i = 0; i < allClaimIds.length && added < limit; i++) {
            if (claims[allClaimIds[i]].status == status) {
                if (found >= offset) {
                    result[added] = allClaimIds[i];
                    added++;
                }
                found++;
            }
        }

        // Resize array
        assembly {
            mstore(result, added)
        }

        return result;
    }

    /**
     * @notice Get total claims count
     */
    function getClaimsCount()
        external
        view
        returns (uint256 total, uint256 approved, uint256 rejected)
    {
        return (totalClaims, approvedClaims, rejectedClaims);
    }

    /**
     * @notice Verify claim data integrity
     * @param claimId The claim to verify
     * @param data The original claim data
     * @return valid Whether the hash matches
     */
    function verifyClaimData(bytes32 claimId, bytes calldata data)
        external
        view
        returns (bool valid)
    {
        return claims[claimId].dataHash == keccak256(data);
    }

    // ============ Admin Functions ============

    function setProviderRegistry(address _providerRegistry) external onlyRole(DEFAULT_ADMIN_ROLE) {
        providerRegistry = ProviderRegistry(_providerRegistry);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // ============ Internal Functions ============

    function _updateStatus(bytes32 claimId, ClaimStatus newStatus) internal {
        ClaimStatus oldStatus = claims[claimId].status;
        claims[claimId].status = newStatus;

        emit ClaimStatusChanged(claimId, oldStatus, newStatus, block.timestamp);
    }

    function _checkAndFinalize(bytes32 claimId) internal {
        Claim storage claim = claims[claimId];

        uint256 totalVerifications = claim.approvalsCount + claim.rejectionsCount;

        // Need minimum threshold
        if (totalVerifications < VERIFICATION_THRESHOLD) {
            return;
        }

        // Don't finalize on a tie - need clear majority
        if (claim.approvalsCount == claim.rejectionsCount) {
            return;
        }

        // Determine outcome based on majority
        bool approved = claim.approvalsCount > claim.rejectionsCount;

        ClaimStatus newStatus = approved ? ClaimStatus.Approved : ClaimStatus.Rejected;

        _updateStatus(claimId, newStatus);
        claim.verifiedAt = block.timestamp;

        // Update provider stats
        providerRegistry.recordClaimResult(claim.provider, approved);

        // Update totals
        if (approved) {
            approvedClaims++;
            totalAmountApproved += claim.amount;
        } else {
            rejectedClaims++;
        }
    }
}`
  }
]

export default function ScannerForm() {
  const router = useRouter()
  const [exampleIndex, setExampleIndex] = useState(0)
  const [code, setCode] = useState(EXAMPLE_CONTRACTS[0].code)
  const [filename, setFilename] = useState(EXAMPLE_CONTRACTS[0].name)
  const [isScanning, setIsScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please enter some code to scan')
      return
    }

    setIsScanning(true)
    setError(null)

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code,
          filename,
        }),
      })

      if (!response.ok) {
        throw new Error('Scan failed')
      }

      const result = await response.json()
      
      // Store result in sessionStorage for the results page to read
      // This works around Next.js module isolation issues with in-memory storage
      sessionStorage.setItem(`scan-result-${result.id}`, JSON.stringify(result))
      
      router.push(`/results/${result.id}`)
    } catch {
      setError('Failed to scan contract. Please try again.')
      setIsScanning(false)
    }
  }

  const loadExample = () => {
    const nextIndex = (exampleIndex + 1) % EXAMPLE_CONTRACTS.length
    const example = EXAMPLE_CONTRACTS[nextIndex]
    setExampleIndex(nextIndex)
    setCode(example.code)
    setFilename(example.name)
    setError(null)
  }

  return (
    <div className="space-y-8">
      {/* Upload Area - Disabled for security */}
      <Card className="border-dashed border-2 border-foreground/30 cursor-not-allowed">
        <CardContent className="p-6">
          <div className="flex flex-col items-center justify-center text-center">
            <div className="p-3 rounded-full mb-4 bg-secondary/20">
              <Upload className="w-6 h-6 text-muted-foreground/60" />
            </div>
            <p className="text-base font-light mb-1 tracking-tight text-foreground/80">
              Drag & drop your Solidity file
            </p>
            <p className="text-xs text-muted-foreground/70 mb-4 font-light">
              or click to browse
            </p>
            <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-amber-500/10 border border-amber-500/20">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              <span className="text-xs text-amber-600 font-medium">
                Disabled — file upload not implemented for security reasons
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Code Editor */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground/70 font-light">File:</span>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="px-3 py-1.5 rounded-md border border-border/50 bg-background/50 text-sm font-light focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/30 transition-all w-64"
              placeholder="contract.sol"
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground/60 hidden sm:inline">
              {EXAMPLE_CONTRACTS[exampleIndex].description}
            </span>
            <Button variant="ghost" size="sm" onClick={loadExample} className="font-light group">
              <Zap className="w-4 h-4 mr-2" />
              <span>Load Example</span>
              <span className="ml-2 text-xs text-muted-foreground/70 tabular-nums">
                {exampleIndex + 1}/{EXAMPLE_CONTRACTS.length}
              </span>
              <ChevronRight className="w-3 h-3 ml-1 opacity-50 group-hover:opacity-100 transition-opacity" />
            </Button>
          </div>
        </div>
        
        <CodeEditor
          value={code}
          onChange={setCode}
          height="630px"
        />
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-3 p-4 rounded-lg bg-destructive/5 border border-destructive/20 text-destructive/90">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span className="text-sm font-light">{error}</span>
        </div>
      )}

      {/* Scan Button */}
      <div className="flex justify-end pt-4">
        <Button
          onClick={handleScan}
          disabled={isScanning || !code.trim()}
          size="lg"
          className="min-w-[200px] font-light"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-5 h-5 mr-2 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Play className="w-5 h-5 mr-2" />
              Scan Contract
            </>
          )}
        </Button>
      </div>
    </div>
  )
}