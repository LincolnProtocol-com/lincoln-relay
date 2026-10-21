// SPDX-License-Identifier: Apache-2.0
// Operator-only cutover control. Missing or invalid configured files fail closed.
import fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';

const reasons=new Set(['RELAY_ACCEPTING','RELAY_MIGRATION_DRAIN','RELAY_CLOUD_STAGED','RELAY_OPERATOR_PAUSED']);
export function createSubmissionControlLoader(filename){
  if(typeof filename!=='string'||!path.isAbsolute(filename))throw new Error('INVALID_SUBMISSION_CONTROL_PATH');
  return async()=>{
    let handle;
    try{
      handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
      const stat=await handle.stat();
      if(!stat.isFile()||stat.size>4096||(stat.mode&0o022)!==0||await fs.realpath(filename)!==filename)throw new Error();
      const value=JSON.parse(await handle.readFile('utf8'));
      if(value?.schema!=='lincoln-relay-submission-control/v1'||value.chainId!==46630||typeof value.enabled!=='boolean'||!reasons.has(value.reason)||value.enabled!==(value.reason==='RELAY_ACCEPTING'))throw new Error();
      return {acceptingNewJobs:value.enabled,reason:value.reason};
    }catch{return {acceptingNewJobs:false,reason:'RELAY_CONTROL_UNAVAILABLE'};}
    finally{await handle?.close();}
  };
}
