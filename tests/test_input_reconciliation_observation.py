"""Guard construction/validation is read-only and bounded on unrelated CSS."""
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_exact_submit_state import spec
from secure_env_ingress.nested_code import _GUARD


def test_combined_metadata_guards_are_observational_and_bounded(nested):
    _, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    leaf.evaluate('''() => {
      const holder = document.createElement('div');
      for (let i = 0; i < 600; i++) holder.append(document.createElement('span'));
      document.body.append(holder);
      const frame = document.createElement('iframe'); frame.style.display = 'none';
      document.body.append(frame);
    }''')
    program = '''({source, spec}) => {
      const make = (SOURCE), samples = [];
      for (const count of [20, 100]) {
        const extra = document.createElement('style');
        extra.textContent = Array.from({length:count}, (_,i)=>`.unused-${i}{color:red}`).join('');
        document.head.append(extra);
        let queries = 0, cssReads = 0;
        const dq = Document.prototype.querySelectorAll, eq = Element.prototype.querySelectorAll;
        const cd = Object.getOwnPropertyDescriptor(CSSStyleSheet.prototype, 'cssRules');
        Document.prototype.querySelectorAll = function(...a){queries++;return dq.apply(this,a)};
        Element.prototype.querySelectorAll = function(...a){queries++;return eq.apply(this,a)};
        Object.defineProperty(CSSStyleSheet.prototype, 'cssRules', {...cd,get(){cssReads++;return cd.get.call(this)}});
        const observer = new MutationObserver(()=>{});
        observer.observe(document,{subtree:true,childList:true,attributes:true,characterData:true});
        const guards = [];
        try {
          const inputs = [...document.querySelectorAll('input')];
          guards.push(make(inputs,false,[document],null,spec,true));
          guards.push(make(inputs,true,[document],null,null,true));
          guards.push(make([...document.querySelectorAll('iframe')],true,[document],null,null,true));
          const constructionQueries = queries;
          cssReads = 0;
          const valid = guards.every(g=>g.valid());
          samples.push({count,valid,queries:constructionQueries,cssReads,
                        sheets:document.styleSheets.length,mutations:observer.takeRecords().length});
        } finally {
          guards.forEach(g=>g.close()); observer.disconnect();
          Document.prototype.querySelectorAll = dq; Element.prototype.querySelectorAll = eq;
          Object.defineProperty(CSSStyleSheet.prototype, 'cssRules', cd); extra.remove();
        }
      }
      return samples;
    }'''.replace('SOURCE', _GUARD)
    result = leaf.evaluate(program, {'source': '', 'spec': spec()})
    assert all(row['valid'] and row['mutations'] == 0 for row in result), result
    assert result[1]['queries'] <= result[0]['queries'] + 96, result
    assert all(row['cssReads'] <= 6 * row['sheets'] for row in result), result
