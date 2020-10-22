function module(e,t,n){let i,o,l,a,c,s,r,u,f,m,_,d,N,E,p,k,h,b,g;n.link("@babel/runtime/helpers/extends",{default(e){i=e}},0),n.link("@babel/runtime/helpers/objectWithoutProperties",{default(e){o=e}},1),n.link("react",{default(e){l=e},useCallback(e){a=e},useEffect(e){c=e},useState(e){s=e},useMemo(e){r=e}},0),n.link("@rocket.chat/fuselage",{Accordion(e){u=e},Field(e){f=e},Select(e){m=e},FieldGroup(e){_=e},ToggleSwitch(e){d=e},Button(e){N=e},Box(e){E=e}},1),n.link("../../../app/ui",{KonchatNotification(e){p=e}},2),n.link("../../contexts/TranslationContext",{useTranslation(e){k=e}},3),n.link("../../contexts/UserContext",{useUserPreference(e){h=e}},4),n.link("../../hooks/useForm",{useForm(e){b=e}},5),n.link("../../contexts/SettingsContext",{useSetting(e){g=e}},6);const D={all:"All_messages",mentions:"Mentions",nothing:"Nothing"},w={mentions:"Email_Notification_Mode_All",nothing:"Email_Notification_Mode_Disabled"},C=e=>{let{onChange:t}=e,n=o(e,["onChange"]);const C=k(),[x,M]=s(),R=h("desktopNotificationRequireInteraction"),y=h("desktopNotifications"),F=h("mobileNotifications"),A=h("emailNotificationMode"),q=g("Accounts_Default_User_Preferences_desktopNotifications"),v=g("Accounts_Default_User_Preferences_mobileNotifications"),I=g("Accounts_AllowEmailNotifications"),{values:T,handlers:L}=b({desktopNotificationRequireInteraction:R,desktopNotifications:y,mobileNotifications:F,emailNotificationMode:A},t),{desktopNotificationRequireInteraction:P,desktopNotifications:S,mobileNotifications:j,emailNotificationMode:U}=T,{handleDesktopNotificationRequireInteraction:B,handleDesktopNotifications:O,handleMobileNotifications:G,handleEmailNotificationMode:H}=L;c(()=>M(window.Notification&&Notification.permission),[]);const K=a(()=>{p.notify({payload:{sender:{username:"rocket.cat"}},title:C("Desktop_Notification_Test"),text:C("This_is_a_desktop_notification")})},[C]),W=a(()=>{window.Notification&&Notification.requestPermission().then(e=>M(e))},[]),Y=r(()=>Object.entries(D).map(e=>{let[t,n]=e;return[t,C(n)]}),[C]),z=r(()=>{const e=Y.slice();return e.unshift(["default","".concat(C("Default")," (").concat(C(D[q]),")")]),e},[q,Y,C]),J=r(()=>{const e=Y.slice();return e.unshift(["default","".concat(C("Default")," (").concat(C(D[v]),")")]),e},[v,Y,C]),Q=r(()=>{const e=Object.entries(w).map(e=>{let[t,n]=e;return[t,C(n)]});return e.unshift(["default","".concat(C("Default")," (").concat(C(w[A]),")")]),e},[C,A]);return l.createElement(u.Item,i({title:C("Notifications")},n),l.createElement(_,null,l.createElement(f,null,l.createElement(f.Label,null,C("Desktop_Notifications")),l.createElement(f.Row,null,"denied"===x&&C("Desktop_Notifications_Disabled"),"granted"===x&&l.createElement(l.Fragment,null,l.createElement(N,{primary:!0,onClick:K},C("Test_Desktop_Notifications"))),"denied"!==x&&"granted"!==x&&l.createElement(l.Fragment,null,l.createElement(N,{primary:!0,onClick:W},C("Enable_Desktop_Notifications"))))),l.createElement(f,null,l.createElement(E,{display:"flex",flexDirection:"row",justifyContent:"spaceBetween",flexGrow:1},l.createElement(f.Label,null,C("Notification_RequireInteraction")),l.createElement(f.Row,null,l.createElement(d,{checked:P,onChange:B}))),l.createElement(f.Hint,null,C("Only_works_with_chrome_version_greater_50"))),l.createElement(f,null,l.createElement(f.Label,null,C("Notification_Desktop_Default_For")),l.createElement(f.Row,null,l.createElement(m,{value:S,onChange:O,options:z}))),l.createElement(f,null,l.createElement(f.Label,null,C("Notification_Mobile_Default_For")),l.createElement(f.Row,null,l.createElement(m,{value:j,onChange:G,options:J}))),l.createElement(f,null,l.createElement(f.Label,null,C("Email_Notification_Mode")),l.createElement(f.Row,null,l.createElement(m,{disabled:!I,value:U,onChange:H,options:Q})),l.createElement(f.Hint,null,I&&C("You_need_to_verifiy_your_email_address_to_get_notications"),!I&&C("Email_Notifications_Change_Disabled")))))};n.exportDefault(C)}

