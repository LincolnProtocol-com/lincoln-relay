// SPDX-License-Identifier: Apache-2.0
// Never serialize an Error: viem errors can contain calldata, proofs and keys.
import {randomBytes} from 'node:crypto';
import {BlockNotFoundError,TransactionReceiptNotFoundError,TransactionNotFoundError,ContractFunctionRevertedError,ContractFunctionZeroDataError} from 'viem';

const APPLICATION_CODES=new Set(`
POINTS_RECEIPTS_DISABLED INVALID_POINTS_REQUEST INVALID_POINTS_ISSUER
ASP_GOVERNANCE_STATE_MISMATCH ASP_POLICY_ENDING ASP_POLICY_IDENTITY_MISMATCH ASP_POLICY_UNAVAILABLE
ASSOCIATION_SET_POLICY_MISMATCH ASSOCIATION_SET_POLICY_NOT_ACCEPTED ASSOCIATION_SET_UNAVAILABLE BODY_TOO_LARGE BROADCAST_HASH_MISMATCH
CHAIN_ID_MISMATCH DUPLICATE_LOG DUPLICATE_NULLIFIER EXIT_COMMITMENT_NOT_FOUND EXIT_CONTEXT_MISMATCH
EXPIRED_SWAP GENESIS_MISMATCH HOST_OR_ORIGIN_DENIED ID_CONFLICT INCOMPLETE_OR_INCONSISTENT_LOGS
INDEXER_CLOSED INVALID_ADDRESS INVALID_ARRAY INVALID_ASP_POLICY_EVENT INVALID_ASSOCIATION_SET
INVALID_CHECKPOINT INVALID_CIPHERTEXT INVALID_COMMITMENT INVALID_DYNAMIC_DEPOSIT
INVALID_EXIT_PROCESSOR_OR_RECIPIENT INVALID_EXIT_SIGNALS INVALID_ID INVALID_INTEGER INVALID_JOB_KIND
INVALID_JSON INVALID_LEAF_INDEX INVALID_LOG INVALID_LOG_IDENTITY INVALID_NULLIFIERS INVALID_OBJECT
INVALID_PROVIDER_EVENT INVALID_PUBLIC_RECIPIENT INVALID_QUOTE_LIMITS INVALID_QUOTE_REQUEST
INVALID_RAGEQUIT_FEE INVALID_RELAY_FEE INVALID_ROUTE_ID INVALID_SERVICE_FEE_AMOUNT
INVALID_SERVICE_FEE_BPS INVALID_SERVICE_FEE_KIND INVALID_SERVICE_FEE_POLICY INVALID_SERVICE_FEE_UNITS
JOB_NOT_FOUND JSON_REQUIRED KNOWN_RECEIPT_MISSING_OR_UNREADABLE MAINNET_RELAY_BROADCAST_HASH_INVALID
MAINNET_RELAY_QUEUE_UNAVAILABLE MAINNET_RELAY_RESERVATION_STATE_UNKNOWN
MAINNET_RELAY_SHARED_FEE_MISMATCH MAINNET_RELAY_SHARED_HASH_MISMATCH MAINNET_RELAY_SHARED_INTENT_MISMATCH
NULLIFIER_RESERVED NULLIFIER_SPENT PAID_SWAP_ADAPTER_REQUIRED PENDING_NONCE POOL_IDENTITY_MISMATCH
POOL_UNDERFUNDED PRIVATE_PAYMENT_AMOUNT_NOT_REQUIRED PUBLIC_FLOW_MISMATCH PUBLIC_SIGNAL_MISMATCH
QUERY_NOT_SUPPORTED QUOTE_UNAVAILABLE RAGEQUIT_ORIGINAL_DEPOSIT_MISMATCH RAGEQUIT_TO_ROUTE_ADAPTER
RELAY_DRAINING ASP_ARTIFACT_ABI_OUTDATED
RELAY_CAPACITY_REACHED RELAY_COST_EXCEEDS_CEILING RELAY_DISABLED RELAY_GAS_BUDGET RELAY_GAS_LIMIT
RELAY_PROCESSOR_MISMATCH RELAY_RECEIPT_FEE_MISMATCH RELAY_RECEIPT_IDENTITY_MISMATCH
RELAY_RECEIPT_REORGANIZED RELAY_REQUEST_QUEUE_FULL RELAY_UNRESOLVED_TRANSACTION
ROUTE_EXECUTION_DISABLED ROUTE_IMMUTABLE_MISMATCH ROUTE_PROFILE_MISMATCH ROUTE_RUNTIME_MISMATCH
ROUTE_RUNTIME_PIN_REQUIRED ROUTE_SNAPSHOT_REORGANIZED ROUTE_TARGET_RUNTIME_MISMATCH RUNTIME_CODE_MISMATCH
SERVICE_FEE_EXCEEDS_OUTPUT SERVICE_FEE_OVERFLOW SERVICE_FEE_POLICY_DISABLED SERVICE_FEE_QUOTE_MISMATCH
SIGNED_INTENT_MISMATCH SNAPSHOT_REORGANIZED STALE_ASP_PROOF STORE_CLOSED STORE_CORRUPT
STORE_IDENTITY_MISMATCH STORE_LOCKED STORE_LOCK_LOST SWAP_ACTION_MISMATCH SWAP_AUTHORIZATION_MISMATCH
SWAP_SERVICE_FEE_POLICY_MISMATCH UNEXPECTED_FIELDS UNEXPECTED_POOL_EVENT UNEXPECTED_REGISTRY_EVENT
UNKNOWN_POOL_LOG UNKNOWN_PROOF_ROOT UNKNOWN_REGISTRY_LOG UNKNOWN_ROUTE UNSUPPORTED_ROUTE_ADAPTER
REQUEST_DEADLINE_EXCEEDED HTTP_REQUEST_CAPACITY_REACHED SHARED_TESTNET_BUDGET_EXCEEDED
SHARED_TESTNET_BUDGET_LOCKED SHARED_TESTNET_BUDGET_UNRESOLVED TESTNET_BUDGET_EXHAUSTED
AGGREGATE_TESTNET_GAS_BUDGET_EXCEEDED BUDGET_IDEMPOTENCY_CONFLICT BUDGET_INTENT_DIGEST_MISMATCH
BUDGET_LOCK_CHANGED BUDGET_NONCANONICAL_RECEIPT BUDGET_RECEIPT_EXCEEDS_CEILING
BUDGET_RECEIPT_FEE_OR_TARGET_MISMATCH BUDGET_RECEIPT_INTENT_MISMATCH BUDGET_RECEIPT_REORGANIZED
BUDGET_SETTLEMENT_CHANGED CROSS_JOURNAL_BUDGET_NONCE_CONFLICT DUPLICATE_BUDGET_NONCE
GLOBAL_RESERVATION_READBACK_FAILED INVALID_ASP_BUDGET_JOB INVALID_ASP_BUDGET_JOURNAL
INVALID_BUDGET_CALL INVALID_BUDGET_FEE_CEILING INVALID_BUDGET_INTENT INVALID_BUDGET_QUANTITY
INVALID_BUDGET_RECEIPT INVALID_BUDGET_RECEIPT_FEE INVALID_BUDGET_SENDER INVALID_FEE_ARCHIVE_ENTRY
INVALID_FEE_RESERVATION INVALID_FEE_SETTLEMENT INVALID_RESERVED_TRANSACTION INVALID_SHARED_FEE_ARCHIVE
MAINNET_ACCOUNT_PENDING_TRANSACTION MAINNET_BROADCAST_HASH_MISMATCH MAINNET_BROADCAST_UNKNOWN
MAINNET_EXTERNAL_PENDING_NONCE MAINNET_GAS_LIMIT_INVALID MAINNET_GAS_LIMIT_TOO_LOW
MAINNET_GAS_PRICE_EXCEEDED MAINNET_GAS_PRICE_INVALID MAINNET_INTENT_ID_INVALID MAINNET_INTENT_ID_REUSED
MAINNET_INTENT_INVALID MAINNET_KEYSTORE_ADDRESS_MISMATCH MAINNET_KEYSTORE_SIGN_FAILED
MAINNET_RECEIPT_FEE_EXCEEDED MAINNET_RECEIPT_IDENTITY_MISMATCH MAINNET_RECEIPT_INTENT_MISMATCH
MAINNET_RECEIPT_LOOKUP_FAILED MAINNET_RECEIPT_REORG MAINNET_RECEIPT_STATUS_INVALID
MAINNET_RESERVATION_ALREADY_SIGNED MAINNET_RESERVATION_CANCELLED MAINNET_RESERVATION_INVALID
MAINNET_RESERVATION_UNKNOWN MAINNET_SIGNED_INTENT_MISMATCH MAINNET_SIGNED_TRANSACTION_INVALID
MAINNET_SIGNER_BALANCE_LOW MAINNET_SIGNER_BUDGET_CHANGED MAINNET_SIGNER_BUDGET_EXCEEDED
MAINNET_SIGNER_GENESIS_MISMATCH MAINNET_SIGNER_IDENTITY_MISMATCH MAINNET_SIGNER_LEDGER_CORRUPT
MAINNET_SIGNER_NONCE_CHANGED MAINNET_SIGNER_NONCE_REGRESSION MAINNET_SIGNER_WRONG_CHAIN
MAINNET_SIGNING_INTENT_INVALID TESTNET_BUDGET_CHAIN_CHANGED UNRESERVED_RELAY_RECEIPT
MAINNET_BROADCAST_REJECTED MAINNET_SIGNER_NONCE_CONFLICT MAINNET_REPRICE_NOT_HIGHER MAINNET_ATTEMPT_LIMIT
MAINNET_MULTIPLE_CANONICAL_ATTEMPTS MAINNET_REJECTED_ATTEMPT_OPERATOR_REQUIRED MAINNET_REJECTED_ATTEMPT_REQUIRES_PREPARE
MAINNET_RECONCILE_OPTIONS_INVALID
UNSAFE_BUDGET_FILE UNSAFE_SHARED_FEE_REFERENCE
TARGET_DEPOSITS_PAUSED TARGET_DEPOSIT_CAP_EXCEEDED TARGET_TOTAL_CAP_EXCEEDED TARGET_TREE_FULL
TARGET_CAPACITY_QUOTE_SNAPSHOT_MISMATCH TARGET_CAPACITY_QUOTE_FEE_MISMATCH TARGET_CAPACITY_CHAIN_MISMATCH
TARGET_CAPACITY_BLOCK_MISMATCH TARGET_CAPACITY_RUNTIME_MISMATCH TARGET_CAPACITY_POOL_MISMATCH TARGET_CAPACITY_SNAPSHOT_CHANGED
INVALID_TARGET_CAPACITY_INTEGER INVALID_TARGET_CAPACITY_SNAPSHOT INVALID_TARGET_CAPACITY_LIMITS
INVALID_TARGET_CAPACITY_FEE INVALID_TARGET_CAPACITY_CLIENT INVALID_TARGET_CAPACITY_POLICY
INVALID_GAS_PRICING_POLICY INVALID_GAS_PRICING_UNITS INVALID_GAS_PRICING_ASSET
INVALID_GAS_PRICING_DECIMALS INVALID_GAS_PRICE_TIMESTAMP INVALID_GAS_PRICE_SOURCE
INVALID_FEE_QUOTE_BOOK INVALID_FEE_QUOTE_PROCESSOR INVALID_FEE_QUOTE_CLOCK INVALID_FEE_QUOTE_REQUEST
INVALID_FEE_QUOTE_FINGERPRINT INVALID_FEE_QUOTE_ID INVALID_FEE_QUOTE_JOB_ID
FEE_QUOTE_REQUIRED FEE_QUOTE_NOT_APPLICABLE FEE_QUOTE_DISABLED FEE_QUOTE_REQUEST_REQUIRED
FEE_QUOTE_POLICY_REQUIRED_FOR_RECOVERY FEE_QUOTE_UNKNOWN FEE_QUOTE_EXPIRED FEE_QUOTE_REPLAY
FEE_QUOTE_STORE_CORRUPT FEE_QUOTE_BOOK_CLOSED FEE_QUOTE_CAPACITY FEE_QUOTE_SHAPE_MISMATCH
FEE_QUOTE_KIND_UNSUPPORTED FEE_QUOTE_GAS_LIMIT FEE_QUOTE_GAS_BELOW_MODEL FEE_QUOTE_AMOUNT_OVERFLOW
FEE_QUOTE_BINDING_MISMATCH FEE_QUOTE_FEE_MISMATCH FEE_QUOTE_RECIPIENT_MISMATCH FEE_QUOTE_COST_EXCEEDED
FEE_QUOTE_COST_INPUT_REQUIRED
FEE_QUOTE_GAS_REQUIRED GAS_ASSET_PRICE_MISSING GAS_ASSET_PRICE_STALE GAS_ASSET_DECIMALS_MISMATCH
GAS_FEE_VALUE_INSUFFICIENT MAINNET_DYNAMIC_FEES_V2_POLICY_REQUIRED FEE_QUOTE_POLICY_REQUIRES_GAS
GAS_PRICE_FEED_LOADER_REQUIRED GAS_PRICE_FEED_UNAVAILABLE GAS_PRICE_FEED_INVALID
SWAP_ECONOMICS_INVALID_INPUT SWAP_ECONOMICS_UNSUPPORTED_ROUTE SWAP_BELOW_MINIMUM_ECONOMIC_AMOUNT
`.trim().split(/\s+/));
const SAFE_TYPES=new Set(['Error','TypeError','RangeError','SyntaxError','ContractFunctionExecutionError','ContractFunctionRevertedError','ContractFunctionZeroDataError','CallExecutionError','TransactionExecutionError','EstimateGasExecutionError','HttpRequestError','WebSocketRequestError','TimeoutError','RpcRequestError','UnknownRpcError','UnknownNodeError','InternalRpcError','ExecutionRevertedError','AbiDecodingZeroDataError','BlockNotFoundError','TransactionReceiptNotFoundError','TransactionNotFoundError','ServiceStoreError']);
const TRANSPORT_TYPES=new Set(['HttpRequestError','WebSocketRequestError','TimeoutError','SocketClosedError','RpcRequestError','UnknownRpcError','InternalRpcError']);
const NODE_NETWORK_CODES=new Set(['ECONNRESET','ECONNREFUSED','ETIMEDOUT','EHOSTUNREACH','ENETUNREACH','ENOTFOUND','EAI_AGAIN','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_BODY_TIMEOUT']);
const STORAGE_CODES=new Set(['EACCES','EPERM','ENOSPC','EIO','EROFS','EMFILE','ENFILE']);
const stages=new WeakMap();
export const validRelayJobId=id=>typeof id==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(id);
export function relayErrorChain(error){const chain=[],seen=new Set();for(let e=error;e&&typeof e==='object'&&!seen.has(e)&&chain.length<12;e=e.cause){seen.add(e);chain.push(e);}return chain;}

/** Name matching is insufficient: every readContract failure has an execution
 * wrapper, including transport errors. Only actual typed causes count.
 */
export function confirmedMissingContractFunction(error){
  const chain=relayErrorChain(error);
  if(chain.some(e=>TRANSPORT_TYPES.has(e.name)||NODE_NETWORK_CODES.has(e.code)))return false;
  return chain.some(e=>e instanceof ContractFunctionZeroDataError||e instanceof ContractFunctionRevertedError&&
    (typeof e.raw==='string'&&/^0x(?:[0-9a-f]{2})*$/i.test(e.raw)||e.reason==='execution reverted'));
}
export async function relayStage(stage,fn){try{return await fn();}catch(error){if(error&&typeof error==='object'&&!stages.has(error))stages.set(error,stage);throw error;}}

export function classifyRelayError(error){
  const chain=relayErrorChain(error),stage=stages.get(error)??'request';
  const known=chain.map(e=>e.code??e.message).find(code=>APPLICATION_CODES.has(code));
  if(known)return {code:known,status:known==='REQUEST_DEADLINE_EXCEEDED'?504:known==='HTTP_REQUEST_CAPACITY_REACHED'||known==='RELAY_DRAINING'||known.startsWith('STORE_')?503:known==='JOB_NOT_FOUND'?404:400,category:'application',stage};
  if(chain.some(e=>e.name==='TimeoutError'||e.code==='ETIMEDOUT'||String(e.code??'').startsWith('UND_ERR_')&&String(e.code).endsWith('_TIMEOUT')))return {code:'RPC_TIMEOUT',status:504,category:'upstream',stage};
  if(chain.some(e=>TRANSPORT_TYPES.has(e.name)||NODE_NETWORK_CODES.has(e.code)))return {code:'RPC_UNAVAILABLE',status:503,category:'upstream',stage};
  // A null lookup response is a typed viem error with no numeric RPC code.
  // Treat it as unavailable upstream state, never an invalid client request.
  // Existing pending-receipt handling remains in the relay reconciliation code.
  if(chain.some(e=>e instanceof BlockNotFoundError||e instanceof TransactionReceiptNotFoundError||e instanceof TransactionNotFoundError))return {code:'RPC_UNAVAILABLE',status:503,category:'upstream',stage};
  if(chain.some(e=>STORAGE_CODES.has(e.code)))return {code:'RELAY_STORAGE_UNAVAILABLE',status:503,category:'storage',stage};
  if(chain.some(e=>e instanceof ContractFunctionRevertedError)&&!confirmedMissingContractFunction(error))return {code:'RPC_UNAVAILABLE',status:503,category:'upstream',stage};
  if(chain.some(e=>e instanceof ContractFunctionRevertedError||e.name==='ExecutionRevertedError'))return {code:'TRANSACTION_REVERTED',status:400,category:'execution',stage};
  if(stage==='signing')return {code:'RELAY_SIGNING_FAILED',status:500,category:'signing',stage};
  if(stage==='estimate')return {code:'GAS_ESTIMATION_FAILED',status:400,category:'execution',stage};
  if(stage==='persistence')return {code:'RELAY_STORAGE_UNAVAILABLE',status:503,category:'storage',stage};
  if(stage==='broadcast'||stage==='reconcile')return {code:'RELAY_SETTLEMENT_UNAVAILABLE',status:503,category:'settlement',stage};
  if(stage==='validation')return {code:'INVALID_RELAY_REQUEST',status:400,category:'validation',stage};
  if(stage==='quote')return {code:'QUOTE_REQUEST_FAILED',status:400,category:'quote',stage};
  return {code:'REQUEST_REJECTED',status:400,category:'unclassified',stage};
}

export function relayJobRecovery({id,job,persisted=false,uncertain=false,inFlight=false}={}){
  if(!validRelayJobId(id))return {jobId:null,jobPersisted:null,jobMayContinue:inFlight,retrySameId:false,useNewId:false,recovery:'KEEP_ORIGINAL_JOB_ID'};
  const exists=Boolean(job),sameIdRetry=exists&&persisted&&!uncertain&&!inFlight&&job.safeSameIdRetry===true&&['rejected','prepared'].includes(job.status);
  const pending=inFlight||exists&&!['confirmed','reverted','cancelled','conflicted'].includes(job.status)&&!sameIdRetry;
  return {jobId:id,jobPersisted:uncertain||exists&&!persisted?null:Boolean(persisted),jobStatus:job?.status??(inFlight?'processing':'not-created'),
    jobStatusPath:`/v3/jobs/${id}`,jobMayContinue:pending,retrySameId:sameIdRetry||!exists&&!inFlight&&!uncertain,useNewId:false,
    recovery:sameIdRetry?'RETRY_IDENTICAL_REQUEST_WITH_ORIGINAL_ID':job?.status==='conflicted'?'OPERATOR_RECONCILIATION_REQUIRED':exists||inFlight||uncertain?'QUERY_JOB_WITH_ORIGINAL_ID':'FIX_CAUSE_AND_RETRY_SAME_ID',
    ...(job?.rejectionReason?{rejectionReason:job.rejectionReason}:{}),...(job?.hash?{transactionHash:job.hash}:{})};
}

export function relayErrorReply(error,{service,chainId,method,path,jobRecovery,errorLogger}={}){
  const classified=classifyRelayError(error),errorId=randomBytes(12).toString('hex');
  // Only enumerated classes/codes and a generated correlation ID reach logs.
  // No error.message, stack, URL, request ID/body, calldata or nested object.
  const event={event:'relay_request_failed',errorId,service,chainId,method:['GET','POST'].includes(method)?method:'OTHER',
    endpoint:['/livez','/healthz','/readyz','/v3/readyz','/v3/config','/v3/state','/v3/association-set','/v3/jobs','/v3/quote','/v3/fees','/v3/aggregate-quote'].includes(path)?path:'/other',
    ...classified,causeTypes:relayErrorChain(error).map(e=>SAFE_TYPES.has(e.name)?e.name:'OtherError')};
  // Keep only a public code-file basename and numeric source position, never
  // the first stack line (which includes the original sensitive message).
  for(const line of String(error?.stack??'').split('\n'))if(/^\s+at /.test(line)){
    const frame=line.match(/\/(service|sdk|state|quote|http|relay-errors|fee-quotes|swap-economics|twap-prices|policy|signer|store)\.mjs:(\d+):(\d+)/);
    if(frame){event.location={file:frame[1]+'.mjs',line:Number(frame[2]),column:Number(frame[3])};break;}
  }
  try{(errorLogger??(value=>process.stderr.write(JSON.stringify(value)+'\n')))(event);}catch{}
  const r=error?.feeRequote;
  const feeRequote=classified.code==='FEE_QUOTE_COST_EXCEEDED'&&r&&
    typeof r.rawGasUnits==='string'&&/^[1-9][0-9]{0,8}$/.test(r.rawGasUnits)&&
    typeof r.gasPriceWei==='string'&&/^(0|[1-9][0-9]{0,8})$/.test(r.gasPriceWei)&&
    BigInt(r.rawGasUnits)<=5000000n&&BigInt(r.gasPriceWei)<=100000000n?
    {feeRequote:{rawGasUnits:r.rawGasUnits,gasPriceWei:r.gasPriceWei}}:{};
  return {status:classified.status,body:{error:classified.code,errorId,...(jobRecovery??{}),...feeRequote}};
}
