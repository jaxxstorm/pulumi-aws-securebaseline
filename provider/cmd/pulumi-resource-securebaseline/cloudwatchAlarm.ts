import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { throws } from "assert";

export interface CloudwatchAlarmArgs {
  alarmNamespace?: pulumi.Input<string>;
  cloudTrailLogGroupName: pulumi.Input<string>;
  pattern: string;
  name: pulumi.Input<string>;
  alarmActions: pulumi.Input<pulumi.Input<string | aws.sns.Topic>[]>;
  alarmDescription?: pulumi.Input<string>;
  tags?: aws.Tags;
}

export class CloudwatchAlarm extends pulumi.ComponentResource {
  public readonly logMetricFilter: aws.cloudwatch.LogMetricFilter;
  public readonly metricAlarm: aws.cloudwatch.MetricAlarm;

  constructor(
    name: string,
    args: CloudwatchAlarmArgs,
    opts?: pulumi.ComponentResourceOptions
  ) {
    super("securebaseline:index:CloudwatchAlarm", name, args, opts);

    this.logMetricFilter = new aws.cloudwatch.LogMetricFilter(
      name,
      {
        logGroupName: args.cloudTrailLogGroupName,
        pattern: args.pattern,
        metricTransformation: {
          namespace: args.alarmNamespace || "CISBenchmark",
          value: "1",
          name: args.name,
        },
      },
      { parent: this }
    );

    this.metricAlarm = new aws.cloudwatch.MetricAlarm(
      name,
      {
        comparisonOperator: "GreaterThanOrEqualToThreshold",
        evaluationPeriods: 1,
        metricName: this.logMetricFilter.id,
        namespace: args.alarmNamespace || "CISBenchmark",
        period: 300,
        statistic: "Sum",
        threshold: 1,
        alarmActions: args.alarmActions,
        treatMissingData: "notBreaching",
        insufficientDataActions: [],
        alarmDescription: args.alarmDescription,
        tags: { ...args.tags },
      },
      { parent: this.logMetricFilter }
    );

    this.registerOutputs({});
  }
}
