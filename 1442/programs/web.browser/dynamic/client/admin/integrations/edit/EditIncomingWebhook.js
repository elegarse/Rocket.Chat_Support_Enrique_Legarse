function module(e,t,n){let a,l,o,i,r,s,c,u,d,m,p,x,E,g,k,b,f,h,C,v,w,D,y,I;function _(e){let{integrationId:t}=e,n=o(e,["integrationId"]);const a=k(),[c,u]=s(),{data:p,state:x,error:E}=b("integrations.get",r(()=>({integrationId:t}),[t,c])),g=()=>u(new Date);return x===f.LOADING?i.createElement(d,l({w:"full",pb:"x24"},n),i.createElement(m,{mbe:"x4"}),i.createElement(m,{mbe:"x8"}),i.createElement(m,{mbe:"x4"}),i.createElement(m,{mbe:"x8"}),i.createElement(m,{mbe:"x4"}),i.createElement(m,{mbe:"x8"})):E?i.createElement(d,l({mbs:"x16"},n),a("Oops_page_not_found")):i.createElement(M,l({data:p.integration,onChange:g},n))}n.link("@babel/runtime/helpers/objectSpread2",{default(e){a=e}},0),n.link("@babel/runtime/helpers/extends",{default(e){l=e}},1),n.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){o=e}},2),n.export({default:()=>_}),n.link("react",{default(e){i=e},useMemo(e){r=e},useState(e){s=e},useCallback(e){c=e}},0),n.link("@rocket.chat/fuselage",{Field(e){u=e},Box(e){d=e},Skeleton(e){m=e},Margins(e){p=e},Button(e){x=e}},1),n.link("./EditIntegrationsPage",{SuccessModal(e){E=e},DeleteWarningModal(e){g=e}},2),n.link("../../../contexts/TranslationContext",{useTranslation(e){k=e}},3),n.link("../../../hooks/useEndpointDataExperimental",{useEndpointDataExperimental(e){b=e},ENDPOINT_STATES(e){f=e}},4),n.link("../../../contexts/ServerContext",{useMethod(e){h=e}},5),n.link("../../../hooks/useEndpointAction",{useEndpointAction(e){C=e}},6),n.link("../../../contexts/RouterContext",{useRoute(e){v=e}},7),n.link("../../../contexts/ToastMessagesContext",{useToastMessageDispatch(e){w=e}},8),n.link("../../../contexts/ModalContext",{useSetModal(e){D=e}},9),n.link("../../../hooks/useForm",{useForm(e){y=e}},10),n.link("../IncomingWebhookForm",{default(e){I=e}},11);const S=e=>{var t,n,a,l,o,i;const r={enabled:e.enabled,channel:null!==(t=e.channel.join(", "))&&void 0!==t?t:"",username:null!==(n=e.username)&&void 0!==n?n:"",name:null!==(a=e.name)&&void 0!==a?a:"",alias:null!==(l=e.alias)&&void 0!==l?l:"",avatarUrl:null!==(o=e.avatarUrl)&&void 0!==o?o:"",emoji:null!==(i=e.emoji)&&void 0!==i?i:"",scriptEnabled:e.scriptEnabled,script:e.script};return r};function M(e){let{data:t,onChange:n}=e,s=o(e,["data","onChange"]);const m=k(),b=w(),{values:f,handlers:_,reset:M}=y(S(t)),T=D(),j=r(()=>({type:"webhook-incoming",integrationId:t._id}),[t._id]),A=C("POST","integrations.remove",j),F=h("updateIncomingIntegration"),O=v("admin-integrations"),P=c(()=>{const e=()=>T(),t=async()=>{const t=await A();t.success&&T(i.createElement(E,{onClose:()=>{e(),O.push({})}}))};T(i.createElement(g,{onDelete:t,onCancel:e}))},[A,O]),R=c(async()=>{try{await F(t._id,a({},f)),b({type:"success",message:m("Integration_updated")}),n()}catch(e){b({type:"error",message:e})}},[t._id,b,f,n,F,m]),G=r(()=>i.createElement(u,null,i.createElement(u.Row,{display:"flex",flexDirection:"column"},i.createElement(d,{display:"flex",flexDirection:"row",justifyContent:"space-between",w:"full"},i.createElement(p,{inlineEnd:"x4"},i.createElement(x,{flexGrow:1,type:"reset",onClick:M},m("Reset")),i.createElement(x,{mie:"none",flexGrow:1,onClick:R},m("Save")))),i.createElement(x,{mbs:"x4",primary:!0,danger:!0,w:"full",onClick:P},m("Delete")))),[P,R,M,m]);return i.createElement(I,l({formHandlers:_,formValues:f,extraData:{_id:t._id,token:t.token},append:G},s))}}

