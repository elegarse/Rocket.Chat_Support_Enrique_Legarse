function module(t,e,n){var o,r,u,c;n.export({useFormatTime:function(){return a}}),n.link("react",{useCallback:function(t){o=t}},0),n.link("moment",{default:function(t){r=t}},1),n.link("../contexts/UserContext",{useUserPreference:function(t){u=t}},2),n.link("../contexts/SettingsContext",{useSetting:function(t){c=t}},3);var i=["h:mm A","H:mm"],a=function(){var t=u("clockMode",!1),e=c("Message_TimeFormat"),n=i[t-1]||e;return o((function(o){switch(t){case 1:case 2:return r(o).format(n);default:return r(o).format(e)}}),[t,e,n])}}

