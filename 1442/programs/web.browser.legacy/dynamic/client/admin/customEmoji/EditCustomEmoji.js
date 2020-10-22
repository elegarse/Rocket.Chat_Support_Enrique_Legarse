function module(e,n,t){var l,r,a,o,c,i,u,s,m,f,E,d,p,C,h,k,b,x,g,j,_,v,w,y,S,D,T,I;t.link("@babel/runtime/regenerator",{default:function(e){l=e}},0),t.link("@babel/runtime/helpers/slicedToArray",{default:function(e){r=e}},1),t.link("@babel/runtime/helpers/extends",{default:function(e){a=e}},2),t.link("@babel/runtime/helpers/objectWithoutProperties",{default:function(e){o=e}},3),t.export({EditCustomEmojiWithData:function(){return F},EditCustomEmoji:function(){return R}}),t.link("react",{default:function(e){c=e},useCallback:function(e){i=e},useState:function(e){u=e},useMemo:function(e){s=e},useEffect:function(e){m=e}},0),t.link("@rocket.chat/fuselage",{Box:function(e){f=e},Button:function(e){E=e},ButtonGroup:function(e){d=e},Margins:function(e){p=e},TextInput:function(e){C=e},Field:function(e){h=e},Icon:function(e){k=e},Skeleton:function(e){b=e},Throbber:function(e){x=e},InputBox:function(e){g=e},Modal:function(e){j=e}},1),t.link("../../contexts/TranslationContext",{useTranslation:function(e){_=e}},2),t.link("../../hooks/useFileInput",{useFileInput:function(e){v=e}},3),t.link("../../hooks/useEndpointDataExperimental",{useEndpointDataExperimental:function(e){w=e},ENDPOINT_STATES:function(e){y=e}},4),t.link("../../hooks/useEndpointUpload",{useEndpointUpload:function(e){S=e}},5),t.link("../../contexts/ModalContext",{useSetModal:function(e){D=e}},6),t.link("../../hooks/useEndpointAction",{useEndpointAction:function(e){T=e}},7),t.link("../../components/basic/VerticalBar",{default:function(e){I=e}},8);var A=function(e){var n=e.onDelete,t=e.onCancel,l=o(e,["onDelete","onCancel"]),r=_();return c.createElement(j,l,c.createElement(j.Header,null,c.createElement(k,{color:"danger",name:"modal-warning",size:20}),c.createElement(j.Title,null,r("Are_you_sure")),c.createElement(j.Close,{onClick:t})),c.createElement(j.Content,{fontScale:"p1"},r("Custom_Emoji_Delete_Warning")),c.createElement(j.Footer,null,c.createElement(d,{align:"end"},c.createElement(E,{ghost:!0,onClick:t},r("Cancel")),c.createElement(E,{primary:!0,danger:!0,onClick:n},r("Delete")))))},U=function(e){var n=e.onClose,t=o(e,["onClose"]),l=_();return c.createElement(j,t,c.createElement(j.Header,null,c.createElement(k,{color:"success",name:"checkmark-circled",size:20}),c.createElement(j.Title,null,l("Deleted")),c.createElement(j.Close,{onClick:n})),c.createElement(j.Content,{fontScale:"p1"},l("Custom_Emoji_Has_Been_Deleted")),c.createElement(j.Footer,null,c.createElement(d,{align:"end"},c.createElement(E,{primary:!0,onClick:n},l("Ok")))))};function F(e){var n=e._id,t=e.cache,l=e.onChange,r=o(e,["_id","cache","onChange"]),i=_(),u=s((function(){return{query:JSON.stringify({_id:n})}}),[n,t]),m=w("emoji-custom.list",u),p=m.data,C=void 0===p?{emojis:{}}:p,h=m.state,k=m.error;return h===y.LOADING?c.createElement(f,{pb:"x20"},c.createElement(b,{mbs:"x8"}),c.createElement(g.Skeleton,{w:"full"}),c.createElement(b,{mbs:"x8"}),c.createElement(g.Skeleton,{w:"full"}),c.createElement(d,{stretch:!0,w:"full",mbs:"x8"},c.createElement(E,{disabled:!0},c.createElement(x,{inheritColor:!0})),c.createElement(E,{primary:!0,disabled:!0},c.createElement(x,{inheritColor:!0}))),c.createElement(d,{stretch:!0,w:"full",mbs:"x8"},c.createElement(E,{primary:!0,danger:!0,disabled:!0},c.createElement(x,{inheritColor:!0})))):k||!C||!C.emojis||C.emojis.update.length<1?c.createElement(f,{fontScale:"h1",pb:"x20"},i("Custom_User_Status_Error_Invalid_User_Status")):c.createElement(R,a({data:C.emojis.update[0],onChange:l},r))}function R(e){var n=e.close,t=e.onChange,a=e.data,b=o(e,["close","onChange","data"]),x=_(),g=a||{},j=g._id,w=g.name,y=g.aliases,F=g.extension,R=a||{},B=u(w),L=r(B,2),N=L[0],O=L[1],P=u(y.join(", ")),M=r(P,2),z=M[0],H=M[1],W=u(),q=r(W,2),G=q[0],J=q[1],V=D(),K=u("/emoji-custom/"+encodeURIComponent(w)+"."+F),Q=r(K,2),X=Q[0],Y=Q[1];m((function(){O(w||""),H(y&&y.join(", ")||"")}),[w,y,R,j]);var Z=i(function(){function e(e){return l.async(function(){function n(n){for(;;)switch(n.prev=n.next){case 0:J(e),Y(URL.createObjectURL(e));case 2:case"end":return n.stop()}}return n}(),null,null,null,Promise)}return e}(),[J]),$=s((function(){return w!==N||z!==y.join(", ")||!!G}),[w,N,z,y,G]),ee=S("emoji-custom.update",{},x("Custom_Emoji_Updated_Successfully")),ne=i(function(){function e(){var e,n;return l.async(function(){function r(r){for(;;)switch(r.prev=r.next){case 0:return(e=new FormData).append("emoji",G),e.append("_id",j),e.append("name",N),e.append("aliases",z),r.next=7,l.awrap(ee(e));case 7:(n=r.sent).success&&t();case 9:case"end":return r.stop()}}return r}(),null,null,null,Promise)}return e}(),[G,j,N,z,ee,t]),te=T("POST","emoji-custom.delete",s((function(){return{emojiId:j}}),[j])),le=i(function(){function e(){var e;return l.async(function(){function r(r){for(;;)switch(r.prev=r.next){case 0:return r.next=2,l.awrap(te());case 2:(e=r.sent).success&&V((function(){return c.createElement(U,{onClose:function(){V(void 0),n(),t()}})}));case 4:case"end":return r.stop()}}return r}(),null,null,null,Promise)}return e}(),[n,te,t]),re=i((function(){return V((function(){return c.createElement(A,{onDelete:le,onCancel:function(){return V(void 0)}})}))}),[le,V]),ae=i((function(e){return H(e.currentTarget.value)}),[H]),oe=v(Z,"emoji"),ce,ie=r(oe,1)[0];return c.createElement(I.ScrollableContent,b,c.createElement(h,null,c.createElement(h.Label,null,x("Name")),c.createElement(h.Row,null,c.createElement(C,{value:N,onChange:function(e){return O(e.currentTarget.value)},placeholder:x("Name")}))),c.createElement(h,null,c.createElement(h.Label,null,x("Aliases")),c.createElement(h.Row,null,c.createElement(C,{value:z,onChange:ae,placeholder:x("Aliases")}))),c.createElement(h,null,c.createElement(h.Label,{alignSelf:"stretch",display:"flex",justifyContent:"space-between",alignItems:"center"},x("Custom_Emoji"),c.createElement(E,{square:!0,onClick:ie},c.createElement(k,{name:"upload",size:"x20"}))),X&&c.createElement(f,{display:"flex",flexDirection:"row",mbs:"none",justifyContent:"center"},c.createElement(p,{inline:"x4"},c.createElement(f,{is:"img",style:{objectFit:"contain"},w:"x120",h:"x120",src:X})))),c.createElement(h,null,c.createElement(h.Row,null,c.createElement(d,{stretch:!0,w:"full"},c.createElement(E,{onClick:n},x("Cancel")),c.createElement(E,{primary:!0,onClick:ne,disabled:!$},x("Save"))))),c.createElement(h,null,c.createElement(h.Row,null,c.createElement(d,{stretch:!0,w:"full"},c.createElement(E,{primary:!0,danger:!0,onClick:re},c.createElement(k,{name:"trash",mie:"x4"}),x("Delete"))))))}}

