function module(e,t,s){let r,i,n,a,o,c,l,u,v;s.link("meteor/meteor",{Meteor(e){r=e}},0),s.link("meteor/reactive-var",{ReactiveVar(e){i=e}},1),s.link("meteor/templating",{Template(e){n=e}},2),s.link("toastr",{default(e){a=e}},3),s.link("../../../../../utils",{t(e){o=e},isEmail(e){c=e},handleError(e){l=e},roomTypes(e){u=e}},4),s.link("../../../../../utils/client",{APIClient(e){v=e}},5),s.link("./visitorTranscript.html");const m=e=>{const t=e.$('[name="subject"]').val(),s=e.$('[name="email"]').val();if(""===s)return e.errorMessage.set(o("Mail_Message_Missing_to")),!1;if(!c(s))return e.errorMessage.set(o("Mail_Message_Invalid_emails",s)),!1;if(""===t)return e.errorMessage.set(o("Mail_Message_Missing_subject")),!1;const r=e.visitor.get(),{visitorEmails:{0:i}}=r;return s===i.address||(e.errorMessage.set(o("Livechat_visitor_email_and_transcript_email_do_not_match")),!1)};n.visitorTranscript.helpers({roomOpen(){const e=n.instance().room.get();return e&&!0===e.open},email(){const e=n.instance().room.get();if(null==e?void 0:e.transcriptRequest)return e.transcriptRequest.email;const t=n.instance().visitor.get();return(null==t?void 0:t.visitorEmails)&&t.visitorEmails.length>0?t.visitorEmails[0].address:void 0},subject(){const e=n.instance().room.get();return(null==e?void 0:e.transcriptRequest)?e.transcriptRequest.subject:o("Transcript_of_your_livechat_conversation")||e&&u.getRoomName(e.t,e)},errorEmail(){const e=n.instance();return e&&e.erroredEmails.get().join(", ")},errorMessage:()=>n.instance().errorMessage.get(),infoMessage:()=>n.instance().infoMessage.get(),transcriptRequested(){const e=n.instance().room.get();return null==e?void 0:e.hasOwnProperty("transcriptRequest")}}),n.visitorTranscript.events({"click .send"(e,t){if(event.preventDefault(),!m(t))return;const s=t.$('[name="subject"]').val(),i=t.$('[name="email"]').val(),n=t.room.get(),{_id:c}=n,u=t.visitor.get(),{token:v}=u;r.call("livechat:sendTranscript",v,c,i,s,e=>{if(null!=e)return l(e);a.success(o("Your_email_has_been_queued_for_sending")),this.save()})},"click .request"(e,t){if(event.preventDefault(),!m(t))return;const s=t.$('[name="subject"]').val(),i=t.$('[name="email"]').val(),n=t.room.get(),{_id:c}=n;r.call("livechat:requestTranscript",c,i,s,e=>{if(null!=e)return l(e);a.success(o("Livechat_transcript_has_been_requested")),this.save()})},"click .discard"(e,t){event.preventDefault();const s=t.room.get(),{_id:i}=s;r.call("livechat:discardTranscript",i,e=>{if(null!=e)return l(e);a.success(o("Livechat_transcript_request_has_been_canceled")),this.save()})},"click .cancel"(){this.cancel()}}),n.visitorTranscript.onCreated((async function(){this.room=new i,this.visitor=new i,this.errorMessage=new i(""),this.infoMessage=new i(""),this.autorun(async()=>{const{visitor:e}=await v.v1.get("livechat/visitors.info?visitorId=".concat(n.currentData().visitorId));this.visitor.set(e)}),this.autorun(async()=>{const{room:e}=await v.v1.get("rooms.info?roomId=".concat(n.currentData().roomId));this.room.set(e),(null==e?void 0:e.transcriptRequest)&&this.infoMessage.set(o("Livechat_transcript_already_requested_warning"))})}))}

