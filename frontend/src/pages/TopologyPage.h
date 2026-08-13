#pragma once

#include "models/TopologyTypes.h"

#include <QMap>
#include <QWidget>

class ApiClient;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QListWidget;
class QListWidgetItem;
class QComboBox;
class QStackedWidget;
class QGraphicsScene;
class QGraphicsView;
class QGraphicsItem;
class QGraphicsLineItem;
class QTableWidget;
class QProgressDialog;

struct TopologyScanRecord {
    QString scanTaskId;
    QString target;
    QString createdAt;
};

class TopologyPage : public QWidget {
    Q_OBJECT

public:
    explicit TopologyPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

private slots:
    void onRefreshScans();
    void onScanClicked(int row, int col);
    void onGenerateTopology();
    void onSaveTopology();
    void onSceneSelectionChanged();
    void onZoomIn();
    void onZoomOut();
    void onResetView();
    void onAddHostNode();
    void onAddEdge();
    void onRemoveSelectedNode();
    void onRemoveSelectedEdge();
    void onApplyDetailEdits();
    void onRemoveSelectedRecord();

private:
    void setupUI();
    void populateTopologyDocument();
    void populateDocumentPlaceholder(const QString &title, const QString &detail);
    void renderTopologyScene();
    void populateNodeList();
    void populateEdgeList();
    void showNodeDetail(const TopologyNodeRecord &node);
    void showEdgeDetail(const TopologyEdgeRecord &edge);
    void showOverviewDetail();
    void syncSelectionToNode(const QString &nodeId);
    void syncSelectionToEdge(const QString &edgeId);
    void applyNodeEdits();
    void applyEdgeEdits();
    void applyPendingEditorChanges();
    void updateEditorState();
    void refreshEdgeNodeOptions();
    void markDocumentDirty(const QString &hint = QString());
    void setStatusMessage(const QString &text, const QString &style = QString());
    TopologyNodeRecord *currentSelectedNode();
    const TopologyNodeRecord *currentSelectedNode() const;
    TopologyEdgeRecord *currentSelectedEdge();
    const TopologyEdgeRecord *currentSelectedEdge() const;
    QString topologyDataDir() const;
    QString topologyDocumentPath(const QString &scanTaskId) const;
    QString defaultTopologyDocumentPath() const;
    QString recentRecordsPath() const;
    bool saveTopologyDocument(QString *errorMessage = nullptr) const;
    bool loadTopologyDocumentFromPath(const QString &path,
                                      TopologyDocument *document,
                                      QString *errorMessage = nullptr) const;
    QString nodeDisplayTitle(const TopologyNodeRecord &node) const;

    // Recent records persistence
    void loadRecentRecords();
    void saveRecentRecords() const;
    void populateRecentRecords();
    void upsertRecentRecord(const TopologyScanRecord &record);

    ApiClient *m_api;
    TopologyDocument m_topologyDocument;
    QString m_loadedTopologyPath;
    QString m_selectedNodeId;
    QString m_selectedEdgeId;
    QMap<QString, QGraphicsItem *> m_nodeItems;
    QMap<QString, QGraphicsLineItem *> m_edgeItems;
    bool m_syncingSelection = false;
    bool m_editorDirty = false;
    bool m_documentDirty = false;
    QString m_selectedScanTaskId;
    QList<TopologyScanRecord> m_recentRecords;

    // Hero stat cards
    QLabel *m_currentStatusValueLabel;
    QLabel *m_currentProgressValueLabel;
    QLabel *m_currentTargetValueLabel;
    QLabel *m_currentSourceValueLabel;
    QLabel *m_lastGeneratedValueLabel;

    // Summary / stats / scope labels
    QLabel *m_summaryLabel;
    QLabel *m_statsLabel;
    QLabel *m_scopeLabel;

    // Left panel
    QLineEdit *m_targetInput;
    QComboBox *m_scanTypeCombo;
    QPushButton *m_createScanBtn;
    QTableWidget *m_scanTaskTable;
    QPushButton *m_generateBtn;
    QPushButton *m_refreshBtn;
    QListWidget *m_recentListWidget;
    QPushButton *m_removeRecordButton;

    // Center panel
    QLabel *m_canvasTitleLabel;
    QLabel *m_canvasSubtitleLabel;
    QLabel *m_statusLabel;
    QGraphicsScene *m_graphScene;
    QGraphicsView *m_graphView;

    // Right panel
    QListWidget *m_nodeListWidget;
    QListWidget *m_edgeListWidget;
    QStackedWidget *m_detailStack;
    QPushButton *m_addNodeButton;
    QPushButton *m_addEdgeButton;
    QPushButton *m_deleteNodeButton;
    QPushButton *m_deleteEdgeButton;
    QPushButton *m_saveTopologyButton;
    QPushButton *m_applyDetailButton;
    QLabel *m_detailHintLabel;
    QLineEdit *m_nodeNameEdit;
    QLineEdit *m_nodeIpEdit;
    QLineEdit *m_nodeHostNameEdit;
    QLineEdit *m_nodeOsEdit;
    QLineEdit *m_nodeTypeEdit;
    QLineEdit *m_nodeVendorEdit;
    QComboBox *m_nodeStatusCombo;
    QPlainTextEdit *m_nodeNoteEdit;
    QPlainTextEdit *m_servicesEdit;
    QComboBox *m_edgeSourceCombo;
    QComboBox *m_edgeTargetCombo;
    QLineEdit *m_edgeLabelEdit;
    QComboBox *m_edgeTypeCombo;
    QPlainTextEdit *m_edgeNoteEdit;

    // Progress dialog (heap-allocated, managed by this page)
    QProgressDialog *m_progressDialog = nullptr;
};
