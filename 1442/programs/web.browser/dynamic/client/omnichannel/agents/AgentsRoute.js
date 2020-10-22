function module(e,t,a){let n,l,c,o,s,i,r,u,m,d,E,x,k,h,f,g,p,T,v,y,C,w,b,A,D,P,R,S;function _(e){let{_id:t,reload:a}=e;const n=g("DELETE","livechat/users/agent/".concat(t)),l=R(),c=S(),i=h(),r=o(async()=>{const e=await n();!0===e.success&&a()}),u=o(e=>{e.stopPropagation();const t=async()=>{try{await r(),c({type:"success",message:i("Agent_removed")})}catch(e){c({type:"error",message:e})}l()};l(s.createElement(P,{onDelete:t,onCancel:()=>l()}))});return s.createElement(d.Cell,{fontScale:"p1",color:"hint",withTruncatedText:!0},s.createElement(x,{small:!0,ghost:!0,title:i("Remove"),onClick:u},s.createElement(E,{name:"trash",size:"x16"})))}function M(e){let{reload:t}=e;const a=h(),n=b("id"),l=A("omnichannel-agents"),c=g("DELETE","livechat/users/agent/".concat(n)),i=R(),r=S(),u=o(async()=>{const e=await c();!0===e.success&&(l.push({}),t())}),m=o(e=>{e.stopPropagation();const t=async()=>{try{await u(),r({type:"success",message:a("Agent_removed")})}catch(e){r({type:"error",message:e})}i()};i(s.createElement(P,{onDelete:t,onCancel:()=>i()}))}),d=o(()=>l.push({context:"edit",id:n}));return[s.createElement(C.Action,{key:a("Remove"),title:a("Remove"),label:a("Remove"),onClick:m,icon:"trash"}),s.createElement(C.Action,{key:a("Edit"),title:a("Edit"),label:a("Edit"),onClick:d,icon:"edit"})]}a.link("@babel/runtime/helpers/objectSpread2",{default(e){n=e}},0),a.export({RemoveAgentButton:()=>_,AgentInfoActions:()=>M}),a.link("@rocket.chat/fuselage-hooks",{useDebouncedValue(e){l=e},useMediaQuery(e){c=e},useMutableCallback(e){o=e}},0),a.link("react",{default(e){s=e},useMemo(e){i=e},useCallback(e){r=e},useState(e){u=e}},1),a.link("@rocket.chat/fuselage",{Box(e){m=e},Table(e){d=e},Icon(e){E=e},Button(e){x=e}},2),a.link("../../components/GenericTable",{Th(e){k=e}},3),a.link("../../contexts/TranslationContext",{useTranslation(e){h=e}},4),a.link("../../hooks/useEndpointDataExperimental",{useEndpointDataExperimental(e){f=e}},5),a.link("../../hooks/useEndpointAction",{useEndpointAction(e){g=e}},6),a.link("../../contexts/AuthorizationContext",{usePermission(e){p=e}},7),a.link("../../components/NotAuthorizedPage",{default(e){T=e}},8),a.link("./AgentsPage",{default(e){v=e}},9),a.link("./AgentEdit",{default(e){y=e}},10),a.link("./AgentInfo",{default(e){C=e}},11),a.link("../../components/basic/avatar/UserAvatar",{default(e){w=e}},12),a.link("../../contexts/RouterContext",{useRouteParameter(e){b=e},useRoute(e){A=e}},13),a.link("../../components/basic/VerticalBar",{default(e){D=e}},14),a.link("../DeleteWarningModal",{default(e){P=e}},15),a.link("../../contexts/ModalContext",{useSetModal(e){R=e}},16),a.link("../../contexts/ToastMessagesContext",{useToastMessageDispatch(e){S=e}},17);const I=e=>"asc"===e?1:-1,N=(e,t)=>{let{text:a,itemsPerPage:l,current:c}=e,[o,s]=t;return i(()=>n({fields:JSON.stringify({name:1,username:1,emails:1,avatarETag:1}),text:a,sort:JSON.stringify({[o]:I(s),usernames:"name"===o?I(s):void 0})},l&&{count:l},{},c&&{offset:c}),[a,l,c,o,s])};function B(){const e=h(),t=p("manage-livechat-agents"),[a,n]=u({text:"",current:0,itemsPerPage:25}),[E,x]=u(["name","asc"]),g=c("(min-width: 1024px)"),P=l(a,500),R=l(E,500),S=N(P,R),I=A("omnichannel-agents"),B=b("context"),z=b("id"),L=o(e=>{const[t,a]=E;x(t!==e?[e,"asc"]:[e,"asc"===a?"desc":"asc"])}),U=o(e=>()=>I.push({context:"info",id:e})),{data:H,reload:J}=f("livechat/users/agent",S)||{},O=i(()=>[s.createElement(k,{key:"name",direction:E[1],active:"name"===E[0],onClick:L,sort:"name",w:"x200"},e("Name")),g&&s.createElement(k,{key:"username",direction:E[1],active:"username"===E[0],onClick:L,sort:"username",w:"x140"},e("Username")),s.createElement(k,{key:"email",direction:E[1],active:"emails.adress"===E[0],onClick:L,sort:"emails.address",w:"x120"},e("Email")),s.createElement(k,{key:"status",direction:E[1],active:"status"===E[0],onClick:L,sort:"status",w:"x120"},e("Livechat_status")),s.createElement(k,{key:"remove",w:"x40"},e("Remove"))].filter(Boolean),[E,L,e,g]),Q=r(t=>{let{emails:a,_id:n,username:l,name:c,avatarETag:o,statusLivechat:i}=t;return(s.createElement(d.Row,{key:n,tabIndex:0,role:"link",onClick:U(n),action:!0,"qa-user-id":n},s.createElement(d.Cell,{withTruncatedText:!0},s.createElement(m,{display:"flex",alignItems:"center"},s.createElement(w,{size:g?"x28":"x40",title:l,username:l,etag:o}),s.createElement(m,{display:"flex",withTruncatedText:!0,mi:"x8"},s.createElement(m,{display:"flex",flexDirection:"column",alignSelf:"center",withTruncatedText:!0},s.createElement(m,{fontScale:"p2",withTruncatedText:!0,color:"default"},c||l),!g&&c&&s.createElement(m,{fontScale:"p1",color:"hint",withTruncatedText:!0}," ","@".concat(l)," "))))),g&&s.createElement(d.Cell,null,s.createElement(m,{fontScale:"p2",withTruncatedText:!0,color:"hint"},l)," ",s.createElement(m,{mi:"x4"})),s.createElement(d.Cell,{withTruncatedText:!0},a&&a.length&&a[0].address),s.createElement(d.Cell,{withTruncatedText:!0},e("available"===i?"Available":"Not_Available")),s.createElement(_,{_id:n,reload:J})))},[g,J,U,e]),V=r(()=>{if(!B)return"";const t=()=>{I.push({})};return(s.createElement(D,{className:"contextual-bar"},s.createElement(D.Header,null,"edit"===B&&e("Edit_User"),"info"===B&&e("User_Info"),s.createElement(D.Close,{onClick:t})),"edit"===B&&s.createElement(y,{uid:z,reload:J}),"info"===B&&s.createElement(C,{uid:z},s.createElement(M,{id:z,reload:J}))))},[e,B,z,I,J]);return t?s.createElement(v,{setParams:n,params:a,onHeaderClick:L,data:H,useQuery:N,reload:J,header:O,renderRow:Q,title:"Agents"},s.createElement(V,null)):s.createElement(T,null)}a.exportDefault(B)}

