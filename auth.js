// auth.js: shared logic for login.html, signup.html and recover.html
// One account stored on this device. Password is hashed (PBKDF2). Session lives in sessionStorage.
const AK='salaryAuthV1',FK='salaryAuthFail',SK='salarySess';
const te=new TextEncoder(),$=id=>document.getElementById(id);
const b64=u=>btoa(String.fromCharCode(...u)),unb=t=>Uint8Array.from(atob(t),c=>c.charCodeAt(0));
async function hashOf(txt,salt){const k=await crypto.subtle.importKey('raw',te.encode(txt),'PBKDF2',false,['deriveBits']);return b64(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:150000},k,256)))}
const nE=e=>e.trim().toLowerCase(),nP=p=>p.replace(/\D/g,''),nU=u=>u.trim().toLowerCase();
const getAcct=()=>{try{return JSON.parse(localStorage.getItem(AK))}catch(e){return null}};
const fails=()=>{try{return JSON.parse(localStorage.getItem(FK))||{n:0,until:0}}catch(e){return{n:0,until:0}}};
const lockLeft=()=>Math.max(0,Math.ceil((fails().until-Date.now())/1000));
function addFail(){const f=fails();f.n++;if(f.n>=5)f.until=Date.now()+Math.min(300,30*(f.n-4))*1000;try{localStorage.setItem(FK,JSON.stringify(f))}catch(e){}}
const clearFail=()=>{try{localStorage.removeItem(FK)}catch(e){}};
const val=id=>($(id)?$(id).value:'');
const tooMany=()=>t('Too many attempts. Try again in {s}s.',{s:lockLeft()});

function eye(id,b){const i=$(id),show=i.type==='password';i.type=show?'text':'password';b.textContent=show?t('Hide'):t('Show')}
function strength(p){let n=0;if(p.length>=6)n++;if(p.length>=10)n++;if(/[A-Z]/.test(p)&&/[a-z]/.test(p))n++;if(/\d/.test(p))n++;if(/[^A-Za-z0-9]/.test(p))n++;
  const b=$('sb');if(b){b.style.width=(p?Math.max(15,n*20):0)+'%';b.style.background=n<=2?'var(--bad)':n<=3?'var(--warn)':'var(--ok)'}}
function err(t,ok){const m=$('msg');m.textContent=t;m.classList.toggle('okk',!!ok);if(!ok){const c=$('acard');c.classList.remove('shake');void c.offsetWidth;c.classList.add('shake')}}
const busy=b=>{const g=$('go');g.disabled=b;g.dataset.t=g.dataset.t||g.textContent;g.textContent=b?t('Please wait…'):g.dataset.t};
const pwCheck=()=>val('p').length<6?t('Password needs at least 6 characters.'):val('p')!==val('p2')?t('Passwords do not match.'):'';
function enter(name){try{sessionStorage.setItem(SK,'1');sessionStorage.setItem('salaryWho',name)}catch(e){}$('msg').textContent=t('Welcome! Opening your calendar…');$('msg').className='msg okk';setTimeout(()=>location.replace('index.html?v=3.4'),350)}

/* ----- page actions ----- */
async function doSignup(){
  const u=val('u').trim(),e=val('e'),tel=val('t');
  const bad=!/^[A-Za-z0-9_.-]{3,}$/.test(u)?t('Username: at least 3 letters, numbers, dot, dash or underscore.'):!/^\S+@\S+\.\S+$/.test(e.trim())?t('Enter a valid email address.'):nP(tel).length<8?t('Enter a valid phone number.'):pwCheck();
  if(bad)return err(bad);
  const old=getAcct();
  if(old){
    if(lockLeft())return err(tooMany());
    if(await hashOf(val('cur'),unb(old.salt))!==old.ph){addFail();return err(lockLeft()?tooMany():t('Current password is wrong.'))}
    clearFail();
  }
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const a={name:u,u:nU(u),salt:b64(salt),ph:await hashOf(val('p'),salt),rh:await hashOf(nE(e)+'|'+nP(tel),salt)};
  localStorage.setItem(AK,JSON.stringify(a));enter(a.name);
}
async function doLogin(){
  if(lockLeft())return err(tooMany());
  const a=getAcct();
  if(!a)return err(t('No account on this device yet. Tap Create account first.'));
  const ok=nU(val('u'))===a.u&&await hashOf(val('p'),unb(a.salt))===a.ph;
  if(!ok){addFail();return err(lockLeft()?tooMany():t('Wrong username or password.'))}
  clearFail();enter(a.name);
}
let verified=false;
async function doRecover(){
  if(lockLeft())return err(tooMany());
  const a=getAcct();
  const ok=a&&nU(val('u'))===a.u&&await hashOf(nE(val('e'))+'|'+nP(val('t')),unb(a.salt))===a.rh;
  if(!ok){addFail();return err(lockLeft()?tooMany():t('Those details do not match this account.'))}
  clearFail();verified=true;
  $('step1').style.display='none';$('step2').style.display='block';$('at').textContent=t('Choose a new password');$('as').textContent=t('Details verified. Pick a new password.');
}
async function doReset(){
  const a=getAcct();if(!verified||!a)return location.replace('login.html');
  const bad=pwCheck();if(bad)return err(bad);
  a.ph=await hashOf(val('p'),unb(a.salt));localStorage.setItem(AK,JSON.stringify(a));enter(a.name);
}

/* ----- wiring: each page says what it is with <body data-page="..."> ----- */
const PAGE=document.body.dataset.page;
const A0=getAcct(),manual=location.search.includes('manual');
// first visit with no account: go straight to sign up (the Log in link on that page adds ?manual)
if((PAGE==='login'||PAGE==='recover')&&!A0&&!manual)location.replace('signup.html');
function setHint(){
  if(PAGE!=='login'||!$('hint'))return;
  if(A0){const n=A0.name;$('hint').textContent=t('Account on this device: {n}',{n:n[0]+'•••'+(n.length>1?n[n.length-1]:'')})}
  else $('hint').textContent=t('No account on this device yet.');
}
if(PAGE==='signup'&&A0){$('replace').style.display='block'}
$('aform').addEventListener('submit',async ev=>{
  ev.preventDefault();
  if(!(window.crypto&&crypto.subtle))return err(t('This browser cannot secure passwords here. Open the app over https.'));
  busy(true);
  try{
    if(PAGE==='signup')await doSignup();
    else if(PAGE==='login')await doLogin();
    else if($('step2').style.display==='block')await doReset();
    else await doRecover();
  }catch(e){err(t('Something went wrong. Try again.'))}
  busy(false);
});

window.onLang=()=>{setHint();document.querySelectorAll('.eye').forEach(b=>{b.textContent=t('Show');b.parentNode.querySelector('input').type='password'})};
applyLang();
