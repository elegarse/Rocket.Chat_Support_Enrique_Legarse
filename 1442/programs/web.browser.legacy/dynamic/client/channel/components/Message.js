function module(e,n,t){var r,l,a,i,c,o,u,m,f;function s(){var e=r(["\n\tdisplay: -webkit-box;\n\toverflow: hidden;\n\t-webkit-line-clamp: 2;\n\t-webkit-box-orient: vertical;\n\tword-break: break-word;\n"]);return s=function(){return e},e}t.link("@babel/runtime/helpers/taggedTemplateLiteralLoose",{default:function(e){r=e}},0),t.link("@babel/runtime/helpers/toConsumableArray",{default:function(e){l=e}},1),t.link("@babel/runtime/helpers/extends",{default:function(e){a=e}},2),t.link("@babel/runtime/helpers/objectWithoutProperties",{default:function(e){i=e}},3),t.export({MessageSkeleton:function(){return x},Container:function(){return d},Header:function(){return b},Username:function(){return h},Timestamp:function(){return g},Message:function(){return E},BodyClamp:function(){return w}}),t.link("react",{default:function(e){c=e}},0),t.link("@rocket.chat/fuselage",{Box:function(e){o=e},Margins:function(e){u=e},Skeleton:function(e){m=e}},1),t.link("@rocket.chat/css-in-js",{css:function(e){f=e}},2);var x=c.memo(function(){function e(e){return c.createElement(E,e,c.createElement(d,{mb:"neg-x2"},c.createElement(m,{variant:"rect",size:"x36"})),c.createElement(d,{width:"1px",mb:"neg-x4",flexGrow:1},c.createElement(b,null,c.createElement(m,{width:"100%"})),c.createElement(w,null,c.createElement(m,null),c.createElement(m,null)),c.createElement(o,{mi:"neg-x8",flexDirection:"row",display:"flex",alignItems:"baseline",mb:"x8"},c.createElement(u,{inline:"x4"},c.createElement(m,null),c.createElement(m,null),c.createElement(m,null)))))}return e}());function d(e){var n=e.children,t=i(e,["children"]);return(c.createElement(o,a({"rcx-message__container":!0,display:"flex",mi:"x4",flexDirection:"column"},t),c.createElement(u,{block:"x2"},n)))}function b(e){var n=e.children;return(c.createElement(o,{"rcx-message__header":!0,display:"flex",flexGrow:0,flexShrink:1,withTruncatedText:!0},c.createElement(o,{mi:"neg-x2",display:"flex",flexDirection:"row",alignItems:"baseline",withTruncatedText:!0,flexGrow:1,flexShrink:1},c.createElement(u,{inline:"x2"}," ",n," "))))}function h(e){return c.createElement(o,a({"rcx-message__username":!0,color:"neutral-800",fontSize:"x14",fontWeight:"600",flexShrink:1,withTruncatedText:!0},e))}function g(e){var n=e.ts;return(c.createElement(o,{"rcx-message__time":!0,fontSize:"c1",color:"neutral-600",flexShrink:0,withTruncatedText:!0},n.toDateString?n.toDateString():n))}function p(e){return null!=e&&"function"==typeof e[Symbol.iterator]}function E(e){var n=e.className,t=i(e,["className"]);return(c.createElement(o,a({"rcx-contextual-message":!0,pi:"x20",pb:"x16",pbs:"x16",display:"flex"},t,{className:l(p(n)?n:[n]).filter(Boolean)})))}t.exportDefault(E);var k=f(s());function w(e){var n=e.className,t=i(e,["className"]);return(c.createElement(o,a({"rcx-message__body":!0,className:[].concat(l(p(n)?n:[n]),[k]).filter(Boolean),flexShrink:1,lineHeight:"1.45",minHeight:"40px"},t)))}}

