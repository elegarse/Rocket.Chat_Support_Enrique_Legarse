function module(e,n,t){var l,o,u,a,c,i,r,s;t.link("react",{default:function(e){l=e}},0),t.link("@rocket.chat/fuselage",{Button:function(e){o=e},Icon:function(e){u=e}},1),t.link("@rocket.chat/fuselage-hooks",{useMutableCallback:function(e){a=e}},2),t.link("../../components/basic/Page",{default:function(e){c=e}},3),t.link("../../contexts/RouterContext",{useRoute:function(e){i=e}},4),t.link("../../contexts/TranslationContext",{useTranslation:function(e){r=e}},5),t.link("./CustomFieldsTable",{default:function(e){s=e}},6);var f=function(){var e=r(),n=i("omnichannel-customfields"),t=a((function(){return n.push({context:"new"})}));return l.createElement(c,null,l.createElement(c.Header,{title:e("Custom_Fields")},l.createElement(o,{small:!0,onClick:t},l.createElement(u,{name:"plus",size:"x16"}))),l.createElement(c.ScrollableContentWithShadow,null,l.createElement(s,null)))};t.exportDefault(f)}

