function module(e,t,l){let a,n,r,o,i,c,m,s,u,p,d,h,_,g,E,y,f,F,k,S,x,I,b,w,C,T,R,U,v;function P(){const e=x(),t=b(),l=T(),[P,B]=E(f(!1)),[L,M]=E(f("upload")),z=C("importerKey"),H=F(()=>U.get(z),[z]),K=I("FileUpload_MaxFileSize"),A=w("admin-import"),D=w("admin-import-new"),q=w("admin-import-prepare"),N=R("POST","uploadImportFile"),O=R("POST","downloadPublicImportFile");k(()=>{z&&!H&&D.replace()},[H,z,D]);const W=v(),G=()=>{A.push()},j=e=>{D.replace({importerKey:e})},J=e=>{M(e)},[Q,V]=f([]),X=async e=>{e=e.originalEvent||e;let{files:t}=e.target;t&&0!==t.length||(t=(null!=e.dataTransfer?e.dataTransfer.files:void 0)||[]),V(Array.from(t))},Y=e=>()=>{V(t=>t.filter(t=>t!==e))},Z=async()=>{B(!0);try{await Promise.all(Array.from(Q,a=>new Promise(n=>{const r=new FileReader;r.readAsDataURL(a),r.onloadend=async()=>{try{await N({binaryContent:r.result.split(";base64,")[1],contentType:a.type,fileName:a.name,importerKey:z}),t({type:"success",message:e("File_uploaded_successfully")})}catch(o){l(o,e("Failed_To_upload_Import_File"))}finally{n()}},r.onerror=()=>n()}))),q.push()}finally{B(!1)}},[$,ee]=E(f("")),te=e=>{ee(e.currentTarget.value)},le=async()=>{B(!0);try{await O({importerKey:z,fileUrl:$}),t({type:"success",message:e("Import_requested_successfully")}),q.push()}catch(a){l(a,e("Failed_To_upload_Import_File"))}finally{B(!1)}},[ae,ne]=E(f("")),re=e=>{ne(e.currentTarget.value)},oe=async()=>{B(!0);try{await O({importerKey:z,fileUrl:ae}),t({type:"success",message:e("Import_requested_successfully")}),q.push()}catch(a){l(a,e("Failed_To_upload_Import_File"))}finally{B(!1)}},ie=g(),ce=g(),me=g(),se="upload"===L&&Z||"url"===L&&le||"path"===L&&oe;return y.createElement(S,{className:"page-settings"},y.createElement(S.Header,{title:e("Import_New_File")},y.createElement(r,null,y.createElement(n,{ghost:!0,onClick:G},y.createElement(m,{name:"back"})," ",e("Back_to_imports")),H&&y.createElement(n,{primary:!0,minHeight:"x40",disabled:P,onClick:se},P?y.createElement(h,{inheritColor:!0}):e("Import")))),y.createElement(S.ScrollableContentWithShadow,null,y.createElement(a,{marginInline:"auto",marginBlock:"neg-x24",width:"full",maxWidth:"x580"},y.createElement(s,{block:"x24"},y.createElement(c,null,y.createElement(c.Label,{alignSelf:"stretch",htmlFor:ie},e("Import_Type")),y.createElement(c.Row,null,y.createElement(u,{id:ie,value:z,disabled:P,placeholder:e("Select_an_option"),onChange:j,options:U.getAll().map(t=>{let{key:l,name:a}=t;return[l,e(a)]})})),H&&y.createElement(c.Hint,null,e("Importer_From_Description",{from:e(H.name)}))),H&&y.createElement(c,null,y.createElement(c.Label,{alignSelf:"stretch",htmlFor:ce},e("File_Type")),y.createElement(c.Row,null,y.createElement(u,{id:ce,value:L,disabled:P,placeholder:e("Select_an_option"),onChange:J,options:[["upload",e("Upload")],["url",e("Public_URL")],["path",e("Server_File_Path")]]}))),H&&y.createElement(y.Fragment,null,"upload"===L&&y.createElement(y.Fragment,null,K>0?y.createElement(o,{type:"warning",marginBlock:"x16"},e("Importer_Upload_FileSize_Message",{maxFileSize:W(K)})):y.createElement(o,{type:"info",marginBlock:"x16"},e("Importer_Upload_Unlimited_FileSize")),y.createElement(c,null,y.createElement(c.Label,{alignSelf:"stretch",htmlFor:me},e("Importer_Source_File")),y.createElement(c.Row,null,y.createElement(p,{type:"file",id:me,onChange:X})),(null==Q?void 0:Q.length)>0&&y.createElement(c.Row,null,Q.map((e,t)=>y.createElement(i,{key:t,onClick:Y(e)},e.name))))),"url"===L&&y.createElement(c,null,y.createElement(c.Label,{alignSelf:"stretch",htmlFor:me},e("File_URL")),y.createElement(c.Row,null,y.createElement(_,{id:me,value:$,onChange:te}))),"path"===L&&y.createElement(c,null,y.createElement(c.Label,{alignSelf:"stretch",htmlFor:me},e("File_Path")),y.createElement(c.Row,null,y.createElement(d,{id:me,value:ae,onChange:re}))))))))}l.link("@rocket.chat/fuselage",{Box(e){a=e},Button(e){n=e},ButtonGroup(e){r=e},Callout(e){o=e},Chip(e){i=e},Field(e){c=e},Icon(e){m=e},Margins(e){s=e},Select(e){u=e},InputBox(e){p=e},TextInput(e){d=e},Throbber(e){h=e},UrlInput(e){_=e}},0),l.link("@rocket.chat/fuselage-hooks",{useUniqueId(e){g=e},useSafely(e){E=e}},1),l.link("react",{default(e){y=e},useState(e){f=e},useMemo(e){F=e},useEffect(e){k=e}},2),l.link("../../components/basic/Page",{default(e){S=e}},3),l.link("../../contexts/TranslationContext",{useTranslation(e){x=e}},4),l.link("../../contexts/SettingsContext",{useSetting(e){I=e}},5),l.link("../../contexts/ToastMessagesContext",{useToastMessageDispatch(e){b=e}},6),l.link("../../contexts/RouterContext",{useRoute(e){w=e},useRouteParameter(e){C=e}},7),l.link("./useErrorHandler",{useErrorHandler(e){T=e}},8),l.link("../../contexts/ServerContext",{useEndpoint(e){R=e}},9),l.link("../../../app/importer/client/index",{Importers(e){U=e}},10),l.link("../../hooks/useFormatMemorySize",{useFormatMemorySize(e){v=e}},11),l.exportDefault(P)}

