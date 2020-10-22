function module(t,e,n){var i,r,o,a,l,c,u,s,f,m,d;n.link("@babel/runtime/regenerator",{default:function(t){i=t}},0),n.link("meteor/meteor",{Meteor:function(t){r=t}},0),n.link("meteor/kadira:flow-router",{FlowRouter:function(t){o=t}},1),n.link("meteor/templating",{Template:function(t){a=t}},2),n.link("meteor/reactive-var",{ReactiveVar:function(t){l=t}},3),n.link("meteor/reactive-dict",{ReactiveDict:function(t){c=t}},4),n.link("underscore",{default:function(t){u=t}},5),n.link("../../../../ui-utils",{modal:function(t){s=t}},6),n.link("../../../../utils",{t:function(t){f=t},handleError:function(t){m=t}},7),n.link("./livechatDepartments.html"),n.link("../../../../utils/client",{APIClient:function(t){d=t}},8),a.livechatDepartments.helpers({departments:function(){return a.instance().departments.get()},isLoading:function(){return a.instance().state.get("loading")},isReady:function(){var t=a.instance();return t.ready&&t.ready.get()},onTableScroll:function(){var t=a.instance();return function(e){if(e.offsetHeight+e.scrollTop>=e.scrollHeight-100)return t.limit.set(t.limit.get()+50)}}});var p=300;a.livechatDepartments.events({"click .remove-department":function(t,e){var n=this;t.preventDefault(),t.stopPropagation(),s.open({title:f("Are_you_sure"),type:"warning",showCancelButton:!0,confirmButtonColor:"#DD6B55",confirmButtonText:f("Yes"),cancelButtonText:f("Cancel"),closeOnConfirm:!1,html:!1},(function(){r.call("livechat:removeDepartment",n._id,(function(t){if(t)return m(t);e.departments.set(e.departments.curValue.filter((function(t){return t._id!==n._id}))),s.open({title:f("Removed"),text:f("Department_removed"),type:"success",timer:1e3,showConfirmButton:!1})}))}))},"click .department-info":function(t){t.preventDefault(),o.go("livechat-department-edit",{_id:this._id})},"keydown #departments-filter":function(t){13===t.which&&(t.stopPropagation(),t.preventDefault())},"keyup #departments-filter":u.debounce((function(t,e){t.stopPropagation(),t.preventDefault(),e.filter.set(t.currentTarget.value)}),300)}),a.livechatDepartments.onCreated((function(){var t=this;this.limit=new l(50),this.filter=new l(""),this.state=new c({loading:!1}),this.ready=new l(!0),this.departments=new l([]),this.autorun(function(){function e(){var e,n,r,o,a;return i.async(function(){function l(l){for(;;)switch(l.prev=l.next){case 0:return e=t.limit.get(),n=t.filter.get(),r="livechat/department?count="+e,n&&(r+="&text="+encodeURIComponent(n)),l.next=6,i.awrap(d.v1.get(r));case 6:o=l.sent,a=o.departments,t.departments.set(a),t.ready.set(!0);case 10:case"end":return l.stop()}}return l}(),null,null,null,Promise)}return e}())}))}

