function module(e,n,t){var i,o,s,u,r,a,l,c,f,d,m,k,p,v,b,h,x;function A(e){var n,t,A=e.uid,E=e.username,S=u(e,["uid","username"]),U=k(),I=l(),_=s(I,2),g=_[0],T=_[1],D=p("UI_Use_Real_Name"),C=p("Accounts_ManuallyApproveNewUsers"),N=function(){return T(new Date)},O=d("users.info",a((function(){return o({},A&&{userId:A},{},E&&{username:E})}),[A,E,g])),y=O.data,F=O.state,L=O.error,R=a((function(){var e,n,t,i=(y||{user:{}}).user,s=i.name,u=i.username,a=i.roles,l=void 0===a?[]:a,c=i.status,f=i.statusText,d=i.bio,m=i.utcOffset,k=i.lastLogin,p=i.nickname;return{name:D?s:u,username:u,lastLogin:k,roles:l.map((function(e,n){return r.createElement(b.Role,{key:n},e)})),bio:d,phone:i.phone,utcOffset:m,customFields:o({},i.customFields,{},C&&!1===i.active&&i.reason&&{Reason:i.reason}),email:null===(e=i.emails)||void 0===e?void 0:null===(n=e.find((function(e){var n;return!!e.address})))||void 0===n?void 0:n.address,createdAt:i.createdAt,status:v.getStatus(c),customStatus:f,nickname:p}}),[y,D]);if(F===m.LOADING)return r.createElement(x,null);if(L)return r.createElement(c,{mbs:"x16"},U("User_not_found"));var j=null===(n=y.user)||void 0===n?void 0:null===(t=n.roles)||void 0===t?void 0:t.includes("admin");return(r.createElement(f,i({},R,{data:y.user,onChange:N,actions:y&&y.user&&r.createElement(h,{isActive:y.user.active,isAdmin:j,_id:y.user._id,username:y.user.username,onChange:N})},S)))}t.link("@babel/runtime/helpers/extends",{default:function(e){i=e}},0),t.link("@babel/runtime/helpers/objectSpread2",{default:function(e){o=e}},1),t.link("@babel/runtime/helpers/slicedToArray",{default:function(e){s=e}},2),t.link("@babel/runtime/helpers/objectWithoutProperties",{default:function(e){u=e}},3),t.export({UserInfoWithData:function(){return A}}),t.link("react",{default:function(e){r=e},useMemo:function(e){a=e},useState:function(e){l=e}},0),t.link("@rocket.chat/fuselage",{Box:function(e){c=e}},1),t.link("../../components/basic/UserInfo",{UserInfo:function(e){f=e}},2),t.link("../../hooks/useEndpointDataExperimental",{useEndpointDataExperimental:function(e){d=e},ENDPOINT_STATES:function(e){m=e}},3),t.link("../../contexts/TranslationContext",{useTranslation:function(e){k=e}},4),t.link("../../contexts/SettingsContext",{useSetting:function(e){p=e}},5),t.link("../../components/basic/UserStatus",{"*":function(e){v=e}},6),t.link("../../components/basic/UserCard",{default:function(e){b=e}},7),t.link("./UserInfoActions",{UserInfoActions:function(e){h=e}},8),t.link("./Skeleton",{FormSkeleton:function(e){x=e}},9)}

