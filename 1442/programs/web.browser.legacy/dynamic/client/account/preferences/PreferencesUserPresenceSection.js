function module(e,n,t){var l,i,a,u,o,r,c,m,f,s,d,b;t.link("@babel/runtime/helpers/extends",{default:function(e){l=e}},0),t.link("@babel/runtime/helpers/objectWithoutProperties",{default:function(e){i=e}},1),t.link("react",{default:function(e){a=e},useCallback:function(e){u=e}},0),t.link("@rocket.chat/fuselage",{Accordion:function(e){o=e},Field:function(e){r=e},NumberInput:function(e){c=e},FieldGroup:function(e){m=e},ToggleSwitch:function(e){f=e}},1),t.link("../../contexts/TranslationContext",{useTranslation:function(e){s=e}},2),t.link("../../contexts/UserContext",{useUserPreference:function(e){d=e}},3),t.link("../../hooks/useForm",{useForm:function(e){b=e}},4);var h=function(e){var n=e.onChange,t=i(e,["onChange"]),h=s(),E=d("enableAutoAway"),k=d("idleTimeLimit"),w=b({enableAutoAway:E,idleTimeLimit:k},n),A=w.values,x=w.handlers,T=A.enableAutoAway,g=A.idleTimeLimit,p=x.handleEnableAutoAway,C=x.handleIdleTimeLimit,y=u((function(e){return C(Number(e.currentTarget.value))}),[C]);return a.createElement(o.Item,l({title:h("User_Presence")},t),a.createElement(m,null,a.createElement(r,{display:"flex",flexDirection:"row",justifyContent:"spaceBetween",flexGrow:1},a.createElement(r.Label,null,h("Enable_Auto_Away")),a.createElement(r.Row,null,a.createElement(f,{checked:T,onChange:p}))),a.createElement(r,null,a.createElement(r.Label,null,h("Idle_Time_Limit")),a.createElement(r.Row,null,a.createElement(c,{value:g,onChange:y})))))};t.exportDefault(h)}

