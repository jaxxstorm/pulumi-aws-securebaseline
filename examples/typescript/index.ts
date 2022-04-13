import * as pulumi from "@pulumi/pulumi";
import * as baseline from "@jaxxstorm/pulumi-aws-securebaseline"

new baseline.Vpc("example")

new baseline.CloudwatchApiAudit("example", {
    cloudTrailLogGroupName: "foo"
})

new baseline.Iam("example", {
    
})
