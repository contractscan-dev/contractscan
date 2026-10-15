// ContractScan UI. All untrusted data (findings, LLM text, patches, errors) is rendered via textContent only.
"use strict";
const T={en:{disc:"⚠️ Not an audit. Automated static analysis (Slither + Aderyn + heuristics) can miss bugs and give false positives.",intro:"Paste a single-file Solidity contract (≤2,000 lines; OpenZeppelin imports OK). We compile and statically analyze it — it is never executed.",go:"Scan",lt:"中文",scanning:"Scanning…",lines:"lines",
buyT:"Full report + auto-fix (pay with USDC on Base)",b1:"$3 USDC · 1 full scan",b5:"$10 USDC · 5 full scans",copyAddr:"Copy address",wpay:"Pay with browser wallet",manualT:"…or send manually from any wallet/exchange, then paste the tx hash below. No signatures are ever requested.",claimB:"Get my redeem code",
copyCode:"Copy code",useCode:"Use code",forget:"Forget code",codeWarn:"SAVE THIS CODE NOW. It holds your credits. Anyone with the code can use it. It can be re-shown from the tx hash only within 1 hour of the first claim.",credits:"Credits",
pay:"Free: 3 scans/day per IP (verdict + top 3). ",sup:"Payment issue? Email ",sumT:"AI summary (verdict above comes from the static-analysis tools, not the AI):",more:"more findings in full report",patch:"Patched contract (re-scanned; review before use)",
send:a=>`Send exactly ${a} USDC on Base (chain 8453) to:`,min:"Minimum $3. Less than $3 grants no credits (flagged for manual refund). Only USDC on Base counts.",copied:"Copied",why:"Why it fired: ",na:"Not analysed (static analysis cannot check these):"},
zh:{disc:"⚠️ 本服务不是审计。自动化静态分析（Slither + Aderyn + 规则）可能漏报或误报。",intro:"粘贴单文件 Solidity 合约（≤2000 行，支持 OpenZeppelin 导入）。我们只编译并做静态分析，绝不执行合约。",go:"扫描",lt:"English",scanning:"扫描中…",lines:"行",
buyT:"完整报告 + 自动修复（用 Base 链 USDC 支付）",b1:"$3 USDC · 1 次完整扫描",b5:"$10 USDC · 5 次完整扫描",copyAddr:"复制地址",wpay:"用浏览器钱包支付",manualT:"……或从任意钱包/交易所手动转账，然后在下方粘贴交易哈希。我们绝不会要求签名。",claimB:"获取兑换码",
copyCode:"复制兑换码",useCode:"使用兑换码",forget:"清除兑换码",codeWarn:"请立即保存此兑换码！次数绑定在兑换码上，任何拿到兑换码的人都能使用。首次领取后 1 小时内可凭交易哈希重新查看。",credits:"剩余次数",
pay:"免费：每 IP 每天 3 次（结论 + 前 3 个问题）。",sup:"付款遇到问题？请发邮件至 ",sumT:"AI 摘要（上方结论来自静态分析工具，而非 AI）：",more:"个问题在完整报告中",patch:"修复后的合约（已复检，使用前请自行审查）",
send:a=>`请在 Base 链（chainId 8453）上向以下地址转账恰好 ${a} USDC：`,min:"最低 $3。少于 $3 不发放次数（将标记人工退款审核）。只认 Base 链 USDC。",copied:"已复制",why:"触发原因：",na:"未分析的内容（静态分析无法检查）："}};
let lang=localStorage.lang==="zh"?"zh":"en",last=null,P=null;
const $=id=>document.getElementById(id);
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=String(text);return e}
const S=x=>(typeof x==="string"?x:(x==null?"":String(x)));
const pk=()=>document.querySelector('input[name=pk]:checked').value;
const AMT={single:3,pack5:10};
function setLang(l){lang=l;localStorage.lang=l;const t=T[l];for(const k of["disc","intro","go","lt","buyT","b1","b5","copyAddr","wpay","manualT","claimB","copyCode","useCode","forget","codeWarn"])$(k).textContent=t[k];
 $("pay").textContent=t.pay;$("sup").textContent=t.sup+(P?P.support_email:"support@contract-scan.dev");payInfo();if(last)render(last);showCr()}
function payInfo(){const b=$("payInfo");b.replaceChildren();if(!P)return;b.append(el("div",null,T[lang].send(AMT[pk()])),el("b",null,P.pay_to),el("div",null,"USDC contract: "+P.usdc_contract),el("small",null,T[lang].min))}
async function api(path,body){const h={"content-type":"application/json","x-cs-ui":"1"};const c=localStorage.csCode;if(c)h["x-cs-code"]=c;
 const r=await fetch(path,{method:"POST",headers:h,body:JSON.stringify(body||{})});let j={};try{j=await r.json()}catch(e){}return{r,j}}
async function showCr(){const c=localStorage.csCode;$("forget").hidden=!c;if(!c){$("cr").textContent="";return}
 const{r,j}=await api("/api/code",{code:c});$("cr").textContent=r.ok?(S(j.code)+" · "+T[lang].credits+": "+S(j.credits)):errText(j)}
function copy(t){navigator.clipboard&&navigator.clipboard.writeText(t).then(()=>say(T[lang].copied))}
function showCode(code){localStorage.csCode=code;$("codeBox").hidden=false;$("codeVal").textContent=code;showCr()}
function errText(j){const d=j&&(j.detail||j);return S((d&&(d.message||d.error))||"error")}
function render(r){const out=$("out");out.replaceChildren();
 if(!r.ok){out.append(el("p","err",r.error||"error"));return}
 out.append(el("div","disc",r.disclaimer&&r.disclaimer[lang]),el("div","v",r.verdict_label&&r.verdict_label[lang]));
 if(r.summary&&r.summary[lang]){out.append(el("small",null,T[lang].sumT),el("p",null,r.summary[lang]))}
 const c=r.counts||{};out.append(el("small",null,`H ${S(c.high)} · M ${S(c.medium)} · L ${S(c.low)} · I ${S(c.info)} | solc ${S(r.solc)} | ${S(r.explainer)}`));
 const fs=(r.findings||[]).slice().sort((a,b)=>(a.severity==="info")-(b.severity==="info"));
 for(const f of fs){const sev=["high","medium","low","info"].includes(f.severity)?f.severity:"info";const d=el("div","f "+sev);
  d.append(el("b",null,`[${S(f["severity_"+lang])}] ${S(f.title)}`)," ",el("small",null,`${S(f.tool)} · ${T[lang].lines} ${(Array.isArray(f.lines)?f.lines:[]).map(Number).join(",")}`),el("br"),document.createTextNode(S(f["explain_"+lang])));if(f.why){d.append(el("br"),el("small",null,T[lang].why+S(f.why)))}out.append(d)}
 if(r.findings_hidden)out.append(el("p",null,"+"+S(r.findings_hidden)+" "+T[lang].more));
 if(Array.isArray(r.not_analyzed)&&r.not_analyzed.length){const ul=el("ul");for(const x of r.not_analyzed)ul.append(el("li",null,S(x)));out.append(el("small",null,T[lang].na),ul)}
 out.append(el("p",null,r.patch_note));
 if(r.patch){out.append(el("h3",null,T[lang].patch),el("pre",null,r.patch))}}
function feedback(r){const fb=$("fb");fb.replaceChildren();if(!r||!r.ok||!r.scan_id){fb.hidden=true;return}fb.hidden=false;
 const zh=lang==="zh";fb.append(el("span",null,zh?"这个结果有用吗？":"Was this result useful? "));
 const c=el("input");c.maxLength=1000;c.size=40;c.placeholder=zh?"可选：补充说明":"Optional comment";
 const send=async u=>{const{r:x}=await api("/api/feedback",{scan_id:r.scan_id,useful:u,comment:c.value});fb.replaceChildren(el("span","mut",x.ok?(zh?"谢谢反馈！":"Thanks for the feedback!"):(zh?"提交失败":"Could not send feedback")))};
 const y=el("button","sec",zh?"有用":"Yes"),n=el("button","sec",zh?"没用":"No");y.type=n.type="button";y.addEventListener("click",()=>send(true));n.addEventListener("click",()=>send(false));
 fb.append(y," ",n," ",c)}
async function go(){$("st").textContent=T[lang].scanning;try{const{r,j}=await api("/api/scan",{source:$("src").value});last=r.ok?j:{ok:false,error:errText(j)};}catch(e){last={ok:false,error:S(e.message)}}$("st").textContent="";render(last);feedback(last);showCr();if(last&&last.ok&&last.scan_id)ev("result_viewed",last.scan_id)}
function ev(name,scan_id,detail){try{fetch("/api/event",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({event:name,scan_id:scan_id||"",detail:detail||""}),keepalive:true}).catch(()=>{})}catch(e){}}
const pad=h=>h.replace(/^0x/,"").toLowerCase().padStart(64,"0");
const say=m=>{$("pst").textContent=S(m)};
async function claimLoop(){const tx=$("txh").value.trim();if(!/^0x[0-9a-fA-F]{64}$/.test(tx)){say("❌ tx hash must be 0x + 64 hex characters");return}localStorage.csPendingTx=tx;
 for(let i=0;i<60;i++){const{r,j}=await api("/api/pay/claim",{tx_hash:tx});
  if(r.ok){delete localStorage.csPendingTx;showCode(j.code);say("✅ "+T[lang].credits+": "+S(j.credits)+(j.note?" — "+S(j.note):""));return}
  if(!j.retryable||j.code==="rate_limited"){say("❌ "+errText(j)+(j.code==="underpaid"?"":" — "+(P?P.support_email:"")));if(j.code!=="rate_limited")delete localStorage.csPendingTx;return}
  say("⏳ "+errText(j));await new Promise(z=>setTimeout(z,6000))}
 say("Still pending. Your payment is safe; click the button again later.")}
async function walletPay(){try{const eth=window.ethereum;if(!eth)throw new Error("No browser wallet found — use the manual option.");
 const amt=AMT[pk()];if(!confirm(`Send ${amt} USDC on Base to ${P.pay_to}?\n(One USDC transfer. No signature or approval.)`))return;
 const[from]=await eth.request({method:"eth_requestAccounts"});const cid="0x"+P.chain_id.toString(16);
 try{await eth.request({method:"wallet_switchEthereumChain",params:[{chainId:cid}]})}catch(e){if(e.code===4902){await eth.request({method:"wallet_addEthereumChain",params:[{chainId:cid,chainName:P.chain_id===8453?"Base":"Base Sepolia",nativeCurrency:{name:"ETH",symbol:"ETH",decimals:18},rpcUrls:[P.chain_id===8453?"https://mainnet.base.org":"https://sepolia.base.org"],blockExplorerUrls:[P.explorer]}]})}else throw e}
 if(parseInt(await eth.request({method:"eth_chainId"}),16)!==P.chain_id)throw new Error("Wrong network in wallet");
 say("Confirm the USDC transfer in your wallet…");
 const tx=await eth.request({method:"eth_sendTransaction",params:[{from,to:P.usdc_contract,data:"0xa9059cbb"+pad(P.pay_to)+pad((amt*1e6).toString(16))}]});
 $("txh").value=tx;await claimLoop()}catch(e){say("❌ "+S(e.message||e))}}
$("go").addEventListener("click",go);$("lt").addEventListener("click",()=>setLang(lang==="en"?"zh":"en"));
for(const r of document.querySelectorAll('input[name=pk]'))r.addEventListener("change",payInfo);
$("copyAddr").addEventListener("click",()=>{ev("pay_clicked",last&&last.scan_id,"copy_address");P&&copy(P.pay_to)});$("copyCode").addEventListener("click",()=>copy($("codeVal").textContent));
$("wpay").addEventListener("click",()=>{ev("pay_clicked",last&&last.scan_id,"wallet");walletPay()});$("claimB").addEventListener("click",()=>{ev("pay_clicked",last&&last.scan_id,"claim");claimLoop()});
$("useCode").addEventListener("click",async()=>{const c=$("codeIn").value.trim().toUpperCase();const{r,j}=await api("/api/code",{code:c});if(r.ok){localStorage.csCode=j.code;$("codeIn").value="";showCr()}else say("❌ "+errText(j))});
$("forget").addEventListener("click",()=>{delete localStorage.csCode;$("codeBox").hidden=true;showCr()});
fetch("/api/pricing").then(r=>r.json()).then(j=>{P=j.payment;setLang(lang);if(localStorage.csPendingTx){$("txh").value=localStorage.csPendingTx;claimLoop()}}).catch(()=>setLang(lang));
