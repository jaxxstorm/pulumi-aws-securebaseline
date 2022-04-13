import * as pulumi from "@pulumi/pulumi";
import * as baseline from "@pulumi/securebaseline";

new baseline.Vpc("example")
