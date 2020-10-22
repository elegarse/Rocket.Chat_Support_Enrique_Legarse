function module(e,t,s){let a,i,n,o,c,r;s.link("@babel/runtime/helpers/objectSpread2",{default(e){a=e}},0),s.link("meteor/templating",{Template(e){i=e}},0),s.link("./contactChatHistoryMessages.html"),s.link("meteor/reactive-var",{ReactiveVar(e){n=e}},1),s.link("underscore",{default(e){o=e}},2),s.link("../../../../../ui-utils/client/lib/messageContext",{messageContext(e){c=e}},3),s.link("../../../../../utils/client",{APIClient(e){r=e}},4);const l=50;i.contactChatHistoryMessages.helpers({messages:()=>i.instance().messages.get(),messageContext(){const e=c.call(this,{rid:i.instance().rid});return a({},e,{settings:a({},e.settings,{showReplyButton:!1,showreply:!1,hideRoles:!0})})},hasMore:()=>i.instance().hasMore.get(),isLoading:()=>i.instance().isLoading.get(),isSearching:()=>i.instance().searchTerm.get().length>0,empty:()=>0===i.instance().messages.get().length}),i.contactChatHistoryMessages.events({"click .js-back":(e,t)=>t.clear(),"scroll .js-list":o.throttle((function(e,t){e.target.scrollTop>=e.target.scrollHeight-e.target.clientHeight&&t.hasMore.get()&&t.offset.set(t.offset.get()+t.limit.get())}),200),"keyup #message-search":o.debounce((function(e,t){if(13===e.keyCode)return e.preventDefault();const{value:s}=e.target;if(40===e.keyCode||38===e.keyCode)return e.preventDefault();t.offset.set(0),t.searchTerm.set(s)}),300)}),i.contactChatHistoryMessages.onCreated((function(){const e=i.currentData();this.rid=e.rid,this.messages=new n([]),this.hasMore=new n(!0),this.offset=new n(0),this.searchTerm=new n(""),this.isLoading=new n(!0),this.limit=new n(50),this.loadMessages=async e=>{this.isLoading.set(!0);const t=this.offset.get(),{messages:s,total:a}=await r.v1.get(e);this.messages.set(0===t?s:this.messages.get().concat(s)),this.hasMore.set(a>this.messages.get().length),this.isLoading.set(!1)},this.autorun(()=>{const e=this.limit.get(),t=this.offset.get(),s=this.searchTerm.get();if(""!==s)return this.loadMessages("chat.search/?roomId=".concat(this.rid,"&searchText=").concat(s,"&count=").concat(e,"&offset=").concat(t,'&sort={"ts": 1}'));this.loadMessages("channels.messages/?roomId=".concat(this.rid,"&count=").concat(e,"&offset=").concat(t,'&sort={"ts": 1}&query={"$or": [ {"t": {"$exists": false} }, {"t": "livechat-close"} ] }'))}),this.autorun(()=>{null!=e.clear&&(this.clear=e.clear)})}))}

