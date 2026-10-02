"""Pre-existing isolated decoration markup used by synthetic browser fixtures."""
HOST_STYLE = ('display:inline-block;position:relative;box-sizing:border-box;width:24px;height:16px;'
              'min-width:24px;max-width:24px;min-height:16px;max-height:16px;contain:strict;'
              'overflow:hidden;pointer-events:none;margin:0;padding:0;border:0;vertical-align:top;flex:0 0 24px')
ICON_STYLE = ('display:none;position:absolute;box-sizing:border-box;left:0;top:0;width:24px;height:16px;'
              'min-width:24px;max-width:24px;min-height:16px;max-height:16px;margin:0;padding:0;border:0;'
              'pointer-events:none;overflow:hidden;contain:strict')
HOST = '''() => {
  const icon=document.querySelector('#brand'), host=document.createElement('span');
  host.id='host';host.style.cssText=%r;
  icon.before(host);host.append(icon);icon.style.cssText=%r;
}''' % (HOST_STYLE, ICON_STYLE)
