/* Public @privy-io/react-auth 3.49.0 AwaitingPasswordlessCodeScreen-BpE4_nMg.js.
 * R handler preserved verbatim. Synthetic callback, React mount and shape only;
 * no Privy provider, network, account, wallet or authentication invocation.
 */
window.fixtureSubmitted=0;
function Fixture(){
  const g=6, [b,_]=React.useState(Array(6).fill(''));
  const u=async code=>{window.fixtureSubmitted++;window.fixtureComplete=code==='123456'}, S=()=>{}, A=()=>{};
  const R=async e=>{e.preventDefault();let r=e.currentTarget.value.replace(" ","");if(""===r)return;if(isNaN(Number(r)))return void S?.("Code should be numeric");A?.();let o=Number(e.currentTarget.name?.charAt(5)),t=[...r||[""]].slice(0,g-o),i=[...b.slice(0,o),...t,...b.slice(o+t.length)];_(i);let n=Math.min(Math.max(o+t.length,0),g-1);if(!isNaN(Number(e.currentTarget.value))){let e=document.querySelector(`input[name=code-${n}]`);e?.focus()}if(i.every((e=>e&&!isNaN(+e)))){let e=document.querySelector(`input[name=code-${n}]`);e?.blur(),await(u?.(i.join("")))}};
  return React.createElement('section',null,
    React.createElement('h2',null,'Enter confirmation code'),
    React.createElement('div',{className:'PasswordlessCodeContainer-sc-6187bfee-0 hOxTXQ'},React.createElement('div',null,React.createElement('div',null,
      b.map((v,i)=>React.createElement('input',{key:i,name:`code-${i}`,type:'text',value:v,onChange:R,inputMode:'numeric',pattern:'[0-9]',autoComplete:'off',className:' '}))))));
}
ReactDOM.createRoot(document.getElementById('fixture-mount')).render(React.createElement(Fixture));
