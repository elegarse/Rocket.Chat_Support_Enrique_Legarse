function module(e,t,n){let a,l,r,o,i,c,s,m,u,d,k,p,x,f,C,b;n.link("@babel/runtime/helpers/extends",{default(e){a=e}},0),n.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){l=e}},1),n.export({AdminSounds:()=>h}),n.link("react",{default(e){r=e},useMemo(e){o=e},useCallback(e){i=e},useState(e){c=e},useEffect(e){s=e}},0),n.link("@rocket.chat/fuselage",{Box(e){m=e},Table(e){u=e},TextInput(e){d=e},Icon(e){k=e},Button(e){p=e}},1),n.link("../../contexts/TranslationContext",{useTranslation(e){x=e}},2),n.link("../../components/GenericTable",{GenericTable(e){f=e},Th(e){C=e}},3),n.link("../../contexts/CustomSoundContext",{useCustomSound(e){b=e}},4);const E=e=>{let{setFilter:t}=e,n=l(e,["setFilter"]);const o=x(),[u,p]=c(""),f=i(e=>p(e.currentTarget.value),[]);return s(()=>{t({text:u})},[u]),r.createElement(m,a({mb:"x16",is:"form",onSubmit:i(e=>e.preventDefault(),[]),display:"flex",flexDirection:"column"},n),r.createElement(d,{flexShrink:0,placeholder:o("Search"),addon:r.createElement(k,{name:"magnifier",size:"x20"}),onChange:f,value:u}))};function h(e){let{data:t,sort:n,onClick:a,onHeaderClick:l,setParams:c,params:s}=e;const d=x(),h=o(()=>[r.createElement(C,{key:"name",direction:n[1],active:"name"===n[0],onClick:l,sort:"name"},d("Name")),r.createElement(C,{w:"x40",key:"action"})],[n]),T=b(),y=i(e=>{T.play(e)},[]),S=e=>{const{_id:t,name:n}=e;return(r.createElement(u.Row,{key:t,onKeyDown:a(t,e),onClick:a(t,e),tabIndex:0,role:"link",action:!0,"qa-user-id":t},r.createElement(u.Cell,{fontScale:"p1",color:"default"},r.createElement(m,{withTruncatedText:!0},n)),r.createElement(u.Cell,{alignItems:"end"},r.createElement(p,{ghost:!0,small:!0,square:!0,"aria-label":d("Play"),onClick:e=>e.preventDefault()&e.stopPropagation()&y(t)},r.createElement(k,{name:"play",size:"x20"})))))};return r.createElement(f,{FilterComponent:E,header:h,renderRow:S,results:t.sounds,total:t.total,setParams:c,params:s})}}

