// SPDX-License-Identifier: Apache-2.0
// Pure fee arithmetic shared by the pinned route quoter and route comparison.
import {MAX_VALUE} from '../phase2-asp/sdk.mjs';

const BPS=10000n;
export const DEFAULT_SERVICE_FEE_BPS=20;
export const MAX_SERVICE_FEE_BPS=100;
export class Phase2AggregateQuoteError extends Error {
  constructor(code){super(code);this.name='Phase2AggregateQuoteError';this.code=code;}
}
function must(value,code){if(!value)throw new Phase2AggregateQuoteError(code);}

/** Output fee is floored; minNetOut is the user's limit AFTER that fee.
 * maxServiceFee is the fee on a fill better than quoted by the same slippage
 * the user accepts on the downside. A cap equal to the quoted fee would make
 * any favourable fill revert (ServiceFeeAboveLimit), and anyone could force
 * that with a tiny trade before inclusion at the relayer's gas cost.
 */
export function netPhase2Quote({grossAmountOut,serviceFeeBps=DEFAULT_SERVICE_FEE_BPS,slippageBPS=100}={}){
  must(typeof grossAmountOut==='bigint'&&grossAmountOut>0n&&grossAmountOut<=MAX_VALUE,'INVALID_AGGREGATE_OUTPUT');
  must(Number.isSafeInteger(serviceFeeBps)&&serviceFeeBps>=0&&serviceFeeBps<=MAX_SERVICE_FEE_BPS,'INVALID_AGGREGATE_FEE');
  must(Number.isSafeInteger(slippageBPS)&&slippageBPS>=1&&slippageBPS<=500,'INVALID_AGGREGATE_SLIPPAGE');
  const bps=BigInt(serviceFeeBps),serviceFeeAmount=grossAmountOut*bps/BPS,netAmountOut=grossAmountOut-serviceFeeAmount;
  const minNetOut=netAmountOut*BigInt(10000-slippageBPS)/BPS;
  must(netAmountOut>0n&&minNetOut>0n,'AGGREGATE_OUTPUT_TOO_SMALL');
  // Exact inverse of gross-floor(gross*bps/10000) >= minNetOut.
  const minGrossOut=(minNetOut-1n)*BPS/(BPS-bps)+1n;
  must(minGrossOut<=MAX_VALUE,'AGGREGATE_GROSS_LIMIT_OVERFLOW');
  const headroomGross=grossAmountOut*BigInt(10000+slippageBPS)/BPS,maxGrossOut=headroomGross<MAX_VALUE?headroomGross:MAX_VALUE;
  const maxServiceFee=maxGrossOut*bps/BPS;
  return {grossAmountOut,serviceFeeBps,serviceFeeAmount,netAmountOut,minNetOut,minGrossOut,maxServiceFee,slippageBPS};
}
