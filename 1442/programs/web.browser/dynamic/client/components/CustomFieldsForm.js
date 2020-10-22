function module(e,t,l){let n,r,a,s,u,o,c,i,m,d,h,f,p,E;l.link("@babel/runtime/helpers/extends",{default(e){n=e}},0),l.link("@babel/runtime/helpers/objectSpread2",{default(e){r=e}},1),l.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){a=e}},2),l.export({default:()=>k}),l.link("react",{default(e){s=e},useMemo(e){u=e},useEffect(e){o=e},useState(e){c=e}},0),l.link("@rocket.chat/fuselage",{TextInput(e){i=e},Select(e){m=e},Field(e){d=e}},1),l.link("../contexts/SettingsContext",{useSetting(e){h=e}},2),l.link("../hooks/useForm",{useForm(e){f=e}},3),l.link("../contexts/TranslationContext",{useTranslation(e){p=e}},4),l.link("../helpers/capitalize",{capitalize(e){E=e}},5);const g=e=>{let{name:t,required:l,minLength:n,maxLength:r,setState:a,state:o,className:c}=e;const m=p(),h=u(()=>{const e=[];return!o&&l&&e.push(m("Field_required")),o.length<n&&e.push(m("Min_length_is",n)),e.join(", ")},[o,l,n,m]);return u(()=>s.createElement(d,{className:c},s.createElement(d.Label,null,t),s.createElement(d.Row,null,s.createElement(i,{name:t,error:h,maxLength:r,flexGrow:1,value:o,required:l,onChange:e=>a(e.currentTarget.value)})),s.createElement(d.Error,null,h)),[t,h,r,o,l,a,c])},F=e=>{let{name:t,required:l,options:n,setState:r,state:a,className:o}=e;const c=p(),i=u(()=>Object.values(n).map(e=>[e,e]),[n]),h=u(()=>!a.length&&l?c("Field_required"):"",[l,a.length,c]);return u(()=>s.createElement(d,{className:o},s.createElement(d.Label,null,t),s.createElement(d.Row,null,s.createElement(m,{name:t,error:h,flexGrow:1,value:a,options:i,required:l,onChange:e=>r(e)})),s.createElement(d.Error,null,h)),[t,h,a,i,l,r,o])},b=e=>{let{formValues:t,formHandlers:l,customFields:u}=e,o=a(e,["formValues","formHandlers","customFields"]);return Object.entries(u).map(e=>{let[a,u]=e;const c=r({key:a,name:a,setState:l["handle".concat(E(a))],state:t[a]},u);return"select"===u.type?s.createElement(F,n({},c,o)):"text"===u.type?s.createElement(g,n({},c,o)):null})};function k(e){let{customFieldsData:t,setCustomFieldsData:l,onLoadFields:i=(()=>{})}=e,m=a(e,["customFieldsData","setCustomFieldsData","onLoadFields"]);const d=h("Accounts_CustomFields"),[p]=c(()=>{try{return JSON.parse(d||"{}")}catch(e){return{}}}),E=Boolean(Object.values(p).length),g=u(()=>Object.entries(p).reduce((e,t)=>{var l;let[n,r]=t;return e[n]=null!==(l=r.defaultValue)&&void 0!==l?l:"",e},{}),[]),{values:F,handlers:k}=f(r({},g,{},t));return o(()=>{i(E),E&&l(F)},[JSON.stringify(F)]),E?s.createElement(b,n({formValues:F,formHandlers:k,customFields:p},m)):null}}

