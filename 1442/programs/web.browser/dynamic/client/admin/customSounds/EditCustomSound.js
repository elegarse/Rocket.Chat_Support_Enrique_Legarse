function module(e,t,n){let l,a,r,o,c,s,i,m,u,d,E,p,C,h,k,f,g,x,S,b,y,_,D,w,T,M,v,F;n.link("@babel/runtime/helpers/extends",{default(e){l=e}},0),n.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){a=e}},1),n.export({EditCustomSound:()=>N}),n.link("react",{default(e){r=e},useCallback(e){o=e},useState(e){c=e},useMemo(e){s=e},useEffect(e){i=e}},0),n.link("@rocket.chat/fuselage",{Box(e){m=e},Button(e){u=e},ButtonGroup(e){d=e},Margins(e){E=e},TextInput(e){p=e},Field(e){C=e},Icon(e){h=e},Skeleton(e){k=e},Throbber(e){f=e},InputBox(e){g=e},Modal(e){x=e}},1),n.link("../../contexts/TranslationContext",{useTranslation(e){S=e}},2),n.link("../../contexts/ServerContext",{useMethod(e){b=e}},3),n.link("../../contexts/ToastMessagesContext",{useToastMessageDispatch(e){y=e}},4),n.link("../../hooks/useFileInput",{useFileInput(e){_=e}},5),n.link("../../hooks/useEndpointDataExperimental",{useEndpointDataExperimental(e){D=e},ENDPOINT_STATES(e){w=e}},6),n.link("./lib",{validate(e){T=e},createSoundData(e){M=e}},7),n.link("../../contexts/ModalContext",{useSetModal(e){v=e}},8),n.link("../../components/basic/VerticalBar",{default(e){F=e}},9);const B=e=>{let{onDelete:t,onCancel:n}=e,l=a(e,["onDelete","onCancel"]);const o=S();return(r.createElement(x,l,r.createElement(x.Header,null,r.createElement(h,{color:"danger",name:"modal-warning",size:20}),r.createElement(x.Title,null,o("Are_you_sure")),r.createElement(x.Close,{onClick:n})),r.createElement(x.Content,{fontScale:"p1"},o("Custom_Sound_Delete_Warning")),r.createElement(x.Footer,null,r.createElement(d,{align:"end"},r.createElement(u,{ghost:!0,onClick:n},o("Cancel")),r.createElement(u,{primary:!0,danger:!0,onClick:t},o("Delete"))))))},I=e=>{let{onClose:t}=e,n=a(e,["onClose"]);const l=S();return(r.createElement(x,n,r.createElement(x.Header,null,r.createElement(h,{color:"success",name:"checkmark-circled",size:20}),r.createElement(x.Title,null,l("Deleted")),r.createElement(x.Close,{onClick:t})),r.createElement(x.Content,{fontScale:"p1"},l("Custom_Sound_Has_Been_Deleted")),r.createElement(x.Footer,null,r.createElement(d,{align:"end"},r.createElement(u,{primary:!0,onClick:t},l("Ok"))))))};function N(e){let{_id:t,cache:n}=e,o=a(e,["_id","cache"]);const c=s(()=>({query:JSON.stringify({_id:t})}),[t]),{data:i,state:E,error:p}=D("custom-sounds.list",c);return E===w.LOADING?r.createElement(m,{pb:"x20"},r.createElement(k,{mbs:"x8"}),r.createElement(g.Skeleton,{w:"full"}),r.createElement(k,{mbs:"x8"}),r.createElement(g.Skeleton,{w:"full"}),r.createElement(d,{stretch:!0,w:"full",mbs:"x8"},r.createElement(u,{disabled:!0},r.createElement(f,{inheritColor:!0})),r.createElement(u,{primary:!0,disabled:!0},r.createElement(f,{inheritColor:!0}))),r.createElement(d,{stretch:!0,w:"full",mbs:"x8"},r.createElement(u,{primary:!0,danger:!0,disabled:!0},r.createElement(f,{inheritColor:!0})))):p||!i||i.sounds.length<1?r.createElement(m,{fontScale:"h1",pb:"x20"},p):r.createElement(O,l({data:i.sounds[0]},o))}function O(e){let{close:t,onChange:n,data:l}=e,k=a(e,["close","onChange","data"]);const f=S(),g=y(),{_id:x,name:D}=l||{},w=l||{},[N,O]=c(""),[A,R]=c(),q=v();i(()=>{O(D||""),R(w||"")},[D,w,x]);const z=b("deleteCustomSound"),H=b("uploadCustomSound"),L=b("insertOrUpdateSound"),G=o(e=>{R(e)},[]),P=s(()=>D!==N||w!==A,[N,D,w,A]),U=o(async e=>{const t=M(e,N,{previousName:D,previousSound:w,_id:x}),n=T(t,e);if(0===n.length){let n;try{n=await L(t)}catch(l){g({type:"error",message:l})}if(t._id=n,t.random=Math.round(1e3*Math.random()),e&&e!==w){g({type:"success",message:f("Uploading_file")});const n=new FileReader;n.readAsBinaryString(e),n.onloadend=()=>{try{return H(n.result,e.type,t),g({type:"success",message:f("File_uploaded")})}catch(l){g({type:"error",message:l})}}}}n.forEach(e=>g({type:"error",message:f("error-the-field-is-required",{field:f(e)})}))},[x,g,L,N,D,w,f,H]),W=o(async()=>{U(A),n()},[U,A,n]),j=o(async()=>{try{await z(x),q(()=>r.createElement(I,{onClose:()=>{q(void 0),t(),n()}}))}catch(e){g({type:"error",message:e}),n()}},[x,t,z,g,n]),J=()=>q(()=>r.createElement(B,{onDelete:j,onCancel:()=>q(void 0)})),[V]=_(G,"audio/mp3");return r.createElement(F.ScrollableContent,k,r.createElement(C,null,r.createElement(C.Label,null,f("Name")),r.createElement(C.Row,null,r.createElement(p,{value:N,onChange:e=>O(e.currentTarget.value),placeholder:f("Name")}))),r.createElement(C,null,r.createElement(C.Label,{alignSelf:"stretch"},f("Sound_File_mp3")),r.createElement(m,{display:"flex",flexDirection:"row",mbs:"none"},r.createElement(E,{inline:"x4"},r.createElement(u,{square:!0,onClick:V},r.createElement(h,{name:"upload",size:"x20"})),A&&A.name||"none"))),r.createElement(C,null,r.createElement(C.Row,null,r.createElement(d,{stretch:!0,w:"full"},r.createElement(u,{onClick:t},f("Cancel")),r.createElement(u,{primary:!0,onClick:W,disabled:!P},f("Save"))))),r.createElement(C,null,r.createElement(C.Row,null,r.createElement(d,{stretch:!0,w:"full"},r.createElement(u,{primary:!0,danger:!0,onClick:J},r.createElement(h,{name:"trash",mie:"x4"}),f("Delete"))))))}}

