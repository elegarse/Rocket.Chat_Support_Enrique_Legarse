function module(e,n,t){var a,l,o,i,u,c,r,s,f;t.link("@babel/runtime/helpers/slicedToArray",{default:function(e){a=e}},0),t.link("react",{default:function(e){l=e},useMemo:function(e){o=e},useState:function(e){i=e}},0),t.link("@rocket.chat/fuselage",{SelectFiltered:function(e){u=e},Field:function(e){c=e}},1),t.link("@rocket.chat/fuselage-hooks",{useMutableCallback:function(e){r=e}},2),t.link("../../../../client/contexts/TranslationContext",{useTranslation:function(e){s=e}},3),t.link("../../../../client/hooks/useTimezoneNameList",{useTimezoneNameList:function(e){f=e}},4);var m=function(e){var n=e.onChange,t=e.data,m=e.className,k=s(),d=i(t),h=a(d,2),T=h[0],b=h[1],g=f(),p=o((function(){return g.map((function(e){return[e,k(e)]}))}),[k,g]),v=r((function(e){b(e)}));return n({name:T}),l.createElement(c,{className:m},l.createElement(c.Label,null,k("Timezone")),l.createElement(c.Row,null,l.createElement(u,{options:p,value:T,onChange:v})))};t.exportDefault(m)}

