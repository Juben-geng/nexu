import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle, ExternalLink, Hash, Loader2, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import "@/lib/api";
import {
  deleteV1ChannelsByChannelId,
  getV1Channels,
  getV1ChannelsSlackOauthUrl,
  postV1ChannelsSlackConnect,
} from "../../lib/api/sdk.gen";

export function ChannelsPage() {
  const queryClient = useQueryClient();

  const { data: channelsData, isLoading: channelsLoading } = useQuery({
    queryKey: ["channels"],
    queryFn: async () => {
      const { data } = await getV1Channels();
      return data;
    },
  });

  const channels = channelsData?.channels ?? [];
  const slackChannel = channels.find((ch) => ch.channelType === "slack");

  return (
    <div className="max-w-2xl">
      <h1 className="mb-1 text-2xl font-bold">Channel Configuration</h1>
      <p className="mb-6 text-muted-foreground">
        Connect your bot to Slack or Discord.
      </p>

      <Tabs defaultValue="slack">
        <TabsList>
          <TabsTrigger value="slack">Slack</TabsTrigger>
          <TabsTrigger value="discord">Discord</TabsTrigger>
        </TabsList>

        <TabsContent value="slack" className="mt-4">
          {slackChannel ? (
            <SlackConnectedView
              channel={slackChannel}
              queryClient={queryClient}
            />
          ) : (
            <SlackConnectView queryClient={queryClient} />
          )}
        </TabsContent>

        <TabsContent value="discord" className="mt-4">
          <DiscordSetupView
            channelsLoading={channelsLoading}
            queryClient={queryClient}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function SlackConnectView({
  queryClient,
}: {
  queryClient: ReturnType<typeof useQueryClient>;
}) {
  const [manualMode, setManualMode] = useState(false);
  const [teamId, setTeamId] = useState("");
  const [teamName, setTeamName] = useState("");
  const [botToken, setBotToken] = useState("");
  const [signingSecret, setSigningSecret] = useState("");

  const connectMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await postV1ChannelsSlackConnect({
        body: { teamId, teamName, botToken, signingSecret },
      });
      if (error) throw new Error(error.message);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      toast.success("Slack connected successfully!");
    },
    onError: (err: Error) => {
      toast.error(err.message);
    },
  });

  const [oauthLoading, setOauthLoading] = useState(false);

  const handleAddToSlack = async () => {
    setOauthLoading(true);
    try {
      const { data, error } = await getV1ChannelsSlackOauthUrl();

      if (error) {
        toast.error(error.message ?? "Failed to generate Slack OAuth URL");
        return;
      }

      if (data?.url) {
        window.location.href = data.url;
      }
    } catch {
      toast.error("Failed to start Slack connection");
    } finally {
      setOauthLoading(false);
    }
  };

  if (!manualMode) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Connect Slack</CardTitle>
          <CardDescription>
            Add your bot to a Slack workspace with one click.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button
            className="w-full"
            onClick={handleAddToSlack}
            disabled={oauthLoading}
          >
            {oauthLoading ? (
              <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            ) : (
              <svg
                className="mr-2 h-5 w-5"
                viewBox="0 0 24 24"
                fill="none"
                aria-hidden="true"
              >
                <path
                  d="M5.042 15.165a2.528 2.528 0 01-2.52 2.523A2.528 2.528 0 010 15.165a2.527 2.527 0 012.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 012.521-2.52 2.527 2.527 0 012.521 2.52v6.313A2.528 2.528 0 018.834 24a2.528 2.528 0 01-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 01-2.521-2.52A2.528 2.528 0 018.834 0a2.528 2.528 0 012.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 012.521 2.521 2.528 2.528 0 01-2.521 2.521H2.522A2.528 2.528 0 010 8.834a2.528 2.528 0 012.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 012.522-2.521A2.528 2.528 0 0124 8.834a2.528 2.528 0 01-2.522 2.521h-2.522V8.834zm-1.271 0a2.528 2.528 0 01-2.521 2.521 2.528 2.528 0 01-2.521-2.521V2.522A2.528 2.528 0 0115.164 0a2.528 2.528 0 012.521 2.522v6.312zM15.164 18.956a2.528 2.528 0 012.521 2.522A2.528 2.528 0 0115.164 24a2.528 2.528 0 01-2.521-2.522v-2.522h2.521zm0-1.271a2.528 2.528 0 01-2.521-2.521 2.528 2.528 0 012.521-2.521h6.314A2.528 2.528 0 0124 15.164a2.528 2.528 0 01-2.522 2.521h-6.314z"
                  fill="currentColor"
                />
              </svg>
            )}
            Add to Slack
          </Button>
          <p className="text-center text-xs text-muted-foreground">
            Or{" "}
            <button
              type="button"
              className="underline"
              onClick={() => setManualMode(true)}
            >
              configure manually
            </button>
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect Slack (Manual)</CardTitle>
        <CardDescription>
          Enter your Slack app credentials to connect.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            connectMutation.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="teamId">Team ID</Label>
            <Input
              id="teamId"
              placeholder="T0123456789"
              value={teamId}
              onChange={(e) => setTeamId(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="teamName">Team Name</Label>
            <Input
              id="teamName"
              placeholder="My Workspace"
              value={teamName}
              onChange={(e) => setTeamName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="botToken">Bot Token</Label>
            <Input
              id="botToken"
              type="password"
              placeholder="xoxb-..."
              value={botToken}
              onChange={(e) => setBotToken(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="signingSecret">Signing Secret</Label>
            <Input
              id="signingSecret"
              type="password"
              placeholder="Signing Secret"
              value={signingSecret}
              onChange={(e) => setSigningSecret(e.target.value)}
              required
            />
          </div>
          <div className="flex gap-2">
            <Button
              type="submit"
              disabled={connectMutation.isPending}
              className="flex-1"
            >
              {connectMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Connect
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => setManualMode(false)}
            >
              Back
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function SlackConnectedView({
  channel,
  queryClient,
}: {
  channel: {
    id: string;
    accountId: string;
    teamName: string | null;
    status: string;
  };
  queryClient: ReturnType<typeof useQueryClient>;
}) {
  const disconnectMutation = useMutation({
    mutationFn: async () => {
      const { error } = await deleteV1ChannelsByChannelId({
        path: { channelId: channel.id },
      });
      if (error) throw new Error(error.message);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      toast.success("Slack disconnected");
    },
  });

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Hash className="h-5 w-5" />
            <div>
              <CardTitle>{channel.teamName ?? channel.accountId}</CardTitle>
              <CardDescription>{channel.accountId}</CardDescription>
            </div>
          </div>
          <Badge variant="success">
            <CheckCircle className="mr-1 h-3 w-3" />
            Connected
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <Separator className="mb-4" />
        <Button
          variant="destructive"
          size="sm"
          onClick={() => disconnectMutation.mutate()}
          disabled={disconnectMutation.isPending}
        >
          <Trash2 className="mr-2 h-4 w-4" />
          Disconnect
        </Button>
      </CardContent>
    </Card>
  );
}

function DiscordSetupView({
  channelsLoading: _channelsLoading,
  queryClient: _queryClient,
}: {
  channelsLoading: boolean;
  queryClient: ReturnType<typeof useQueryClient>;
}) {
  const [step, setStep] = useState(1);
  const totalSteps = 5;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect Discord</CardTitle>
        <CardDescription>
          Step {step} of {totalSteps} &mdash; Follow the guide to set up your
          Discord bot.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {step === 1 && (
          <div className="space-y-3">
            <h3 className="font-medium">1. Create a Discord Application</h3>
            <p className="text-sm text-muted-foreground">
              Go to the Discord Developer Portal and create a new application.
            </p>
            <Button variant="outline" size="sm" asChild>
              <a
                href="https://discord.com/developers/applications"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open Developer Portal
                <ExternalLink className="ml-2 h-3 w-3" />
              </a>
            </Button>
          </div>
        )}
        {step === 2 && (
          <div className="space-y-3">
            <h3 className="font-medium">2. Configure Bot Permissions</h3>
            <p className="text-sm text-muted-foreground">
              In your application settings, go to Bot &rarr; enable
              &ldquo;Message Content Intent&rdquo; under Privileged Gateway
              Intents.
            </p>
          </div>
        )}
        {step === 3 && (
          <div className="space-y-3">
            <h3 className="font-medium">3. Set Interactions Endpoint</h3>
            <p className="text-sm text-muted-foreground">
              In General Information, set the Interactions Endpoint URL to:
            </p>
            <code className="block rounded bg-muted p-2 text-sm">
              https://api.nexu.dev/discord/interactions
            </code>
          </div>
        )}
        {step === 4 && (
          <div className="space-y-3">
            <h3 className="font-medium">4. Enter Credentials</h3>
            <p className="text-sm text-muted-foreground">
              Copy your Bot Token and Public Key from the Developer Portal.
            </p>
            <div className="space-y-2">
              <Label>Bot Token</Label>
              <Input type="password" placeholder="MTxx..." />
              <Label>Public Key</Label>
              <Input placeholder="Public Key" />
              <Label>Guild ID</Label>
              <Input placeholder="Server ID" />
            </div>
          </div>
        )}
        {step === 5 && (
          <div className="space-y-3">
            <h3 className="font-medium">5. Invite & Test</h3>
            <p className="text-sm text-muted-foreground">
              Invite the bot to your server using the OAuth2 URL generator in
              the Developer Portal. Then test by mentioning the bot.
            </p>
          </div>
        )}

        <Separator />
        <div className="flex justify-between">
          <Button
            variant="outline"
            disabled={step === 1}
            onClick={() => setStep((s) => s - 1)}
          >
            Previous
          </Button>
          {step < totalSteps ? (
            <Button onClick={() => setStep((s) => s + 1)}>Next</Button>
          ) : (
            <Button onClick={() => toast.info("Discord setup coming soon")}>
              Complete Setup
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
