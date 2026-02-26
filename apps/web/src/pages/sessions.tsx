import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useQuery } from "@tanstack/react-query";
import { Clock, Hash, MessageCircle, MessageSquare } from "lucide-react";
import { useParams } from "react-router-dom";
import { getV1SessionsById } from "../../lib/api/sdk.gen";

const CHANNEL_ICONS: Record<string, string> = {
  slack: "\uD83D\uDCAC",
  discord: "\uD83C\uDFAE",
  telegram: "\u2708\uFE0F",
  web: "\uD83C\uDF10",
  whatsapp: "\uD83D\uDCF1",
};

function formatTime(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return d.toLocaleDateString();
}

function EmptyState() {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="flex flex-col items-center text-center">
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
          <MessageSquare className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="mb-2 text-lg font-medium text-foreground">
          Select a session
        </h3>
        <p className="max-w-sm text-sm text-muted-foreground">
          Pick a session from the sidebar to view details, or start a
          conversation through your connected channels.
        </p>
      </div>
    </div>
  );
}

export function SessionsPage() {
  const { id } = useParams<{ id: string }>();

  const { data: session } = useQuery({
    queryKey: ["session", id],
    queryFn: async () => {
      if (!id) {
        throw new Error("Session id is required");
      }
      const { data } = await getV1SessionsById({ path: { id } });
      return data;
    },
    enabled: !!id,
  });

  if (!id) {
    return <EmptyState />;
  }

  if (!session) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
        Loading...
      </div>
    );
  }

  return (
    <div className="flex h-full items-start justify-center">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg">{session.title}</CardTitle>
            <Badge
              variant={session.status === "active" ? "default" : "secondary"}
            >
              {session.status}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            {session.channelType && (
              <div>
                <span className="text-muted-foreground">Channel</span>
                <div className="mt-1 flex items-center gap-1.5">
                  <span>
                    {CHANNEL_ICONS[session.channelType] ?? "\uD83D\uDCAC"}
                  </span>
                  <span className="capitalize">{session.channelType}</span>
                </div>
              </div>
            )}
            <div>
              <span className="text-muted-foreground">Messages</span>
              <div className="mt-1 flex items-center gap-1.5">
                <MessageCircle className="h-3.5 w-3.5 text-muted-foreground" />
                <span>{session.messageCount}</span>
              </div>
            </div>
            <div>
              <span className="text-muted-foreground">Last activity</span>
              <div className="mt-1 flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                <span>
                  {formatTime(session.lastMessageAt || session.updatedAt)}
                </span>
              </div>
            </div>
            <div>
              <span className="text-muted-foreground">Created</span>
              <div className="mt-1 flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                <span>{formatTime(session.createdAt)}</span>
              </div>
            </div>
          </div>

          <Separator />

          <div className="text-xs text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <Hash className="h-3 w-3" />
              <span className="font-mono">{session.sessionKey}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
