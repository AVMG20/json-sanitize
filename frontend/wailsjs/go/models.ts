export namespace main {
	
	export class ModelStatus {
	    model: string;
	    state: string;
	    error: string;
	    sizeBytes: number;
	    expiresAt: string;
	    idleSeconds: number;
	
	    static createFrom(source: any = {}) {
	        return new ModelStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.model = source["model"];
	        this.state = source["state"];
	        this.error = source["error"];
	        this.sizeBytes = source["sizeBytes"];
	        this.expiresAt = source["expiresAt"];
	        this.idleSeconds = source["idleSeconds"];
	    }
	}
	export class SanitizeResponse {
	    output: string;
	    valid: boolean;
	    diffs: string[];
	    changes: sanitizer.Change[];
	    counts: Record<string, number>;
	    chunks: number;
	    entities: number;
	    unmatched: string[];
	    ms: number;
	
	    static createFrom(source: any = {}) {
	        return new SanitizeResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.output = source["output"];
	        this.valid = source["valid"];
	        this.diffs = source["diffs"];
	        this.changes = this.convertValues(source["changes"], sanitizer.Change);
	        this.counts = source["counts"];
	        this.chunks = source["chunks"];
	        this.entities = source["entities"];
	        this.unmatched = source["unmatched"];
	        this.ms = source["ms"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

