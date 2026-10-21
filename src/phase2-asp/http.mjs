// SPDX-License-Identifier: Apache-2.0
// HTTP deadlines are response bounds, not transaction cancellation. A job that
// has entered the durable relay queue must be recovered by its original ID.
import http from 'node:http';

export function normalizeHttpLimits({requestDeadlineMs=45000,maxInFlight=32,maxConnections=64}={}){
  for(const [value,max]of [[requestDeadlineMs,120000],[maxInFlight,128],[maxConnections,256]]){
    if(!Number.isSafeInteger(value)||value<1||value>max)throw new Error('INVALID_HTTP_LIMITS');
  }
  if(maxConnections<maxInFlight)throw new Error('INVALID_HTTP_LIMITS');
  return {requestDeadlineMs,maxInFlight,maxConnections};
}

/** All response paths, including late RPC completion, use this guard. */
export function serviceJson(res,status,value,headers={}){
  return serviceJsonBytes(res,status,JSON.stringify(value),headers);
}

/** Writes an already serialised JSON body (large snapshots are serialised once per snapshot, not per request). */
export function serviceJsonBytes(res,status,bytes,headers={}){
  if(res.destroyed||res.writableEnded||res.headersSent)return false;
  res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers});
  res.end(bytes);return true;
}

/** Answers a conditional GET: 304 when the client already holds this exact body, else the body with its validator. */
export function serviceJsonVersioned(req,res,{bytes,etag}){
  const tags=String(req.headers['if-none-match']??'').split(',').map(tag=>tag.trim()).filter(Boolean);
  if(tags.includes(etag)||tags.includes('*')){
    if(res.destroyed||res.writableEnded||res.headersSent)return false;
    res.writeHead(304,{'ETag':etag,'Cache-Control':'no-cache','X-Content-Type-Options':'nosniff'});res.end();return true;
  }
  return serviceJsonBytes(res,200,bytes,{'ETag':etag,'Cache-Control':'no-cache'});
}

export function createBoundedHttpServer(handler,options={}){
  const {requestDeadlineMs,maxInFlight,maxConnections}=normalizeHttpLimits(options);
  let active=0;
  const server=http.createServer(async(req,res)=>{
    if(active>=maxInFlight){req.resume();return serviceJson(res,503,{error:'HTTP_REQUEST_CAPACITY_REACHED',...(req.method==='POST'&&req.url==='/v3/jobs'?{requestAccepted:false,jobId:null,jobPersisted:null,jobMayContinue:true,retrySameId:false,useNewId:false,recovery:'QUERY_JOB_WITH_ORIGINAL_ID'}:{})},{'Retry-After':'1',Connection:'close'});}
    active++;
    const timer=setTimeout(()=>{
      // A response deadline cannot undo an already signed/broadcast job. Do not
      // advertise the timeout as a rejected transaction or free the work slot.
      const jobMayContinue=req.method==='POST'&&req.url==='/v3/jobs';
      const failure=res.relayErrorReply?.(new Error('REQUEST_DEADLINE_EXCEEDED'));
      serviceJson(res,failure?.status??504,failure?.body??{error:'REQUEST_DEADLINE_EXCEEDED',jobMayContinue,...(jobMayContinue?{recovery:'QUERY_JOB_WITH_ORIGINAL_ID'}:{})},{Connection:'close'});
      req.resume();
    },requestDeadlineMs);
    timer.unref();
    const cleanup=()=>clearTimeout(timer);
    res.once('close',cleanup);
    try{await handler(req,res);}
    catch(error){const failure=res.relayErrorReply?.(error);serviceJson(res,failure?.status??500,failure?.body??{error:'REQUEST_FAILED'});}
    finally{clearTimeout(timer);res.off('close',cleanup);active--;}
  });
  // The old 20s socket inactivity timer destroyed otherwise valid slow RPC
  // requests before JSON could be returned. Use an absolute application bound;
  // headers/body, keep-alive, sockets and outstanding work remain bounded.
  server.timeout=0;server.requestTimeout=15000;server.headersTimeout=10000;
  server.keepAliveTimeout=5000;server.maxHeadersCount=32;server.maxRequestsPerSocket=100;server.maxConnections=maxConnections;
  return server;
}
