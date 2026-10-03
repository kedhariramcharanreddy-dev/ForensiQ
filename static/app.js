function openModal(id){document.getElementById(id).classList.add('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
window.addEventListener('click',e=>{if(e.target.classList.contains('modal'))e.target.classList.remove('show')})
async function reanalyze(id){const box=document.getElementById('aiBox');box.innerHTML='<div class="ai-badge">✦ AI</div><p>Analyzing evidence indicators…</p>';const r=await fetch('/evidence/'+id+'/analyze',{method:'POST'});const d=await r.json();box.innerHTML='<div class="ai-badge">✦ AI</div><p><b>'+d.risk+' risk.</b> '+d.summary+'</p>';setTimeout(()=>location.reload(),900)}
async function loadRiskChart(){const el=document.getElementById('riskChart');if(!el)return;const d=await fetch('/api/stats').then(r=>r.json());new Chart(el,{type:'doughnut',data:{labels:['Low','Medium','High','Critical'],datasets:[{data:[d.Low||0,d.Medium||0,d.High||0,d.Critical||0]}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{boxWidth:10,font:{size:10}}}}}})}

async function verifyIntegrity(id){const r=await fetch("/evidence/"+id+"/verify",{method:"POST"});const d=await r.json();alert("Integrity: "+d.status+(d.message?"\n"+d.message:""));location.reload()}
