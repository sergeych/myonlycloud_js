import { MyoCloud } from "./MyoCloud";
import { CloudObject } from "./CloudObject";
import { CloudElement } from "./CloudData";

const privateDocumentTagPrefix = "Inbox.Private_";

export type InboxDefinitionRecord = { id: string, element: CloudElement };
export type InboxInternalData = {
  nameHash: string;
  name: string;
  destinationId: string;
}

export class Inbox {

  readonly ready: Promise<Inbox>;
  private utag!: string;
  private definition!: CloudObject<InboxInternalData>;

  constructor(private service: MyoCloud, private idr: InboxDefinitionRecord) {
    this.ready = this.initialize();
  }

  private async initialize(): Promise<Inbox> {
    const d = await this.service.objectByUniqueTag<InboxInternalData>(
      await this.service.scramble(privateDocumentTagPrefix + this.idr.id)
    );
    if (!d) throw new MyoCloud.Exception("inbox: failed to load box definition object");
    this.definition = d;
    return this;
  }

  get name(): string { return this.definition.data.name;}

  get id(): string { return this.idr.id; }
}
