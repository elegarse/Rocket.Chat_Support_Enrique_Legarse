function module(e,n,t){var o,i,l,r,u,a,c,f,s,m,b,k;t.link("@babel/runtime/helpers/slicedToArray",{default:function(e){o=e}},0),t.link("@babel/runtime/helpers/toConsumableArray",{default:function(e){i=e}},1),t.link("@babel/runtime/helpers/extends",{default:function(e){l=e}},2),t.link("@babel/runtime/helpers/objectWithoutProperties",{default:function(e){r=e}},3),t.link("react",{default:function(e){u=e},useMemo:function(e){a=e}},0),t.link("@rocket.chat/fuselage",{ButtonGroup:function(e){c=e},Menu:function(e){f=e},Option:function(e){s=e}},1),t.link("../../../components/basic/UserInfo",{default:function(e){m=e}},2),t.link("../../hooks/useUserInfoActions",{useUserInfoActions:function(e){b=e},useUserInfoActionsSpread:function(e){k=e}},3);var p=function(e){var n=e.user,t=e.rid,p=k(b(n,t)),d=p.actions,h=p.menu,x=h&&u.createElement(f,{mi:"x4",ghost:!1,small:!1,renderItem:function(e){var n=e.label,t=n.label,o=n.icon,i=r(e,["label"]);return(u.createElement(s,l({},i,{label:t,icon:o})))},flexShrink:0,key:"menu",options:h}),A=a((function(){return[].concat(i(d.map((function(e){var n=o(e,2),t=n[0],i=n[1],l=i.label,r=i.icon,a=i.action;return(u.createElement(m.Action,{key:t,title:l,label:l,onClick:a,icon:r}))}))),[x]).filter(Boolean)}),[d,x]);return u.createElement(c,{mi:"neg-x4",flexShrink:0,flexWrap:"nowrap",withTruncatedText:!0,justifyContent:"center",flexShrink:0},A)};t.exportDefault(p)}

