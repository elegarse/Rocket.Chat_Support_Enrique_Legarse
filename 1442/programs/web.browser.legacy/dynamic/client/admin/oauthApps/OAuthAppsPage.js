function module(e,t,n){var l,u,a,c,i,o,r,f,p,m;function s(){var e=i(),t=r("admin-oauth-apps"),n=o("context"),s=o("id");return l.createElement(c,{flexDirection:"row"},l.createElement(c,null,l.createElement(c.Header,{title:e("OAuth_Applications")},n&&l.createElement(u,{alignSelf:"flex-end",onClick:function(){return t.push({})}},l.createElement(a,{name:"back"}),e("Back")),!n&&l.createElement(u,{primary:!0,alignSelf:"flex-end",onClick:function(){return t.push({context:"new"})}},l.createElement(a,{name:"plus"}),e("New_Application"))),l.createElement(c.Content,null,!n&&l.createElement(f,null),"edit"===n&&l.createElement(p,{_id:s}),"new"===n&&l.createElement(m,null))))}n.export({OAuthAppsPage:function(){return s}}),n.link("react",{default:function(e){l=e}},0),n.link("@rocket.chat/fuselage",{Button:function(e){u=e},Icon:function(e){a=e}},1),n.link("../../components/basic/Page",{default:function(e){c=e}},2),n.link("../../contexts/TranslationContext",{useTranslation:function(e){i=e}},3),n.link("../../contexts/RouterContext",{useRouteParameter:function(e){o=e},useRoute:function(e){r=e}},4),n.link("./OAuthAppsTable",{default:function(e){f=e}},5),n.link("./OAuthEditApp",{default:function(e){p=e}},6),n.link("./OAuthAddApp",{default:function(e){m=e}},7),n.exportDefault(s)}

