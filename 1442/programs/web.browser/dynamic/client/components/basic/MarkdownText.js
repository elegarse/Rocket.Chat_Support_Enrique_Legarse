function module(e,t,n){let l,r,s,u,o,i,a;n.link("@babel/runtime/helpers/extends",{default(e){l=e}},0),n.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){r=e}},1),n.link("underscore.string",{default(e){s=e}},0),n.link("@rocket.chat/fuselage",{Box(e){u=e}},1),n.link("react",{default(e){o=e},useMemo(e){i=e}},2),n.link("marked",{default(e){a=e}},3),a.InlineLexer.rules.gfm.strong=/^\*\*(?=\S)([\s\S]*?\S)\*\*(?!\*)|^\*(?=\S)([\s\S]*?\S)\*(?!\*)/,a.InlineLexer.rules.gfm.em=/^__(?=\S)([\s\S]*?\S)__(?!_)|^_(?=\S)([\s\S]*?\S)_(?!_)/;const c={gfm:!0,headerIds:!1};function m(e){let{content:t,preserveHtml:n=!1}=e,m=r(e,["content","preserveHtml"]);const S=i(()=>t&&a(n?t:s.escapeHTML(t),c),[t,n]);return(o.createElement(u,l({dangerouslySetInnerHTML:{__html:S},withRichContent:!0},m)))}n.exportDefault(m)}

